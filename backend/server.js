require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// In production, only your own website may call this API.
// Locally (FRONTEND_URL not set) any origin is allowed, so development still works.
const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(',').map(s => s.trim().replace(/\/$/, ''))
  : null;
app.use(cors(allowedOrigins ? { origin: allowedOrigins } : undefined));
app.use(express.json());

// =====================================================
// AUTH MIDDLEWARE
// Works out who is calling from the login token (not from anything the browser claims)
// =====================================================
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Please log in to continue.' });
  }

  try {
    // Supabase checks the token's signature and expiry for us
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data || !data.user) {
      return res.status(401).json({ error: 'Your session has expired. Please log in again.' });
    }

    const { data: profile } = await supabase
      .from('profiles')
      .select('id, role, full_name')
      .eq('id', data.user.id)
      .maybeSingle();

    if (!profile) {
      return res.status(401).json({ error: 'Account not found. Please log in again.' });
    }

    req.user = { id: profile.id, role: profile.role, name: profile.full_name };
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// Only let certain roles through, e.g. requireRole('Patient')
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'You do not have access to this.' });
    }
    next();
  };
}

// =====================================================
// PUBLIC ROUTES
// =====================================================

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'Backend is running smoothly on Windows!' });
});

// Registration endpoint
app.post('/api/auth/register', async (req, res) => {
  const { 
    email, 
    password, 
    fullName, 
    role, 
    phone, 
    dateOfBirth, 
    gender, 
    address, 
    city 
  } = req.body;

  try {
    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password,
    });
    if (authError) return res.status(400).json({ error: authError.message });

    const userId = authData.user.id;

    const { error: profileError } = await supabase
      .from('profiles')
      .insert([
        {
          id: userId,
          full_name: fullName,
          email: email,
          role: role,
          phone: phone || null,
          date_of_birth: dateOfBirth || null,
          gender: gender || null,
          city: city || null,
          address: address || null
        }
      ]);

    if (profileError) return res.status(400).json({ error: profileError.message });

    if (role === 'Clinic') {
      await supabase.from('clinics').insert([
        { admin_user_id: userId, name: fullName, city: city || 'Unknown', address: address || 'Main Facility', contact_phone: phone }
      ]);
    } else if (role === 'Doctor') {
      await supabase.from('doctors').insert([
        { doctor_user_id: userId, name: fullName, specialty: 'General Medicine' }
      ]);
    }

    res.status(201).json({ message: 'User registered successfully!', user: authData.user });
  } catch (err) {
    console.error('Registration server error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Login endpoint - only registered users with the correct password get in
app.post('/api/auth/login', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';
  const role = req.body.role; // 'Patient' | 'Doctor' | 'Clinic'

  if (!email || !password) {
    return res.status(400).json({ error: 'Please enter your email and password.' });
  }

  try {
    // 1. Is this email registered at all?
    const { data: profile, error: profileErr } = await supabase
      .from('profiles')
      .select('id, full_name, email, role')
      .ilike('email', email)
      .maybeSingle();

    if (profileErr) return res.status(500).json({ error: profileErr.message });
    if (!profile) {
      return res.status(404).json({ error: 'No account found with this email. Please register first.' });
    }

    // 2. Verify the password with Supabase Auth
    // (separate client so the shared one keeps its own session)
    const authClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
    const { data: authData, error: authError } = await authClient.auth.signInWithPassword({ email, password });

    if (authError) {
      const msg = /not confirmed/i.test(authError.message)
        ? 'Please confirm your email address before logging in.'
        : 'Incorrect password. Please try again.';
      return res.status(401).json({ error: msg });
    }

    // 3. Make sure they are using the right portal
    if (role && profile.role !== role) {
      return res.status(403).json({
        error: `This email is registered as a ${profile.role}, not a ${role}. Please choose the correct role.`
      });
    }

    // 4. Extra details for the dashboards
    let specialty = null;
    if (profile.role === 'Doctor') {
      const { data: doc } = await supabase
        .from('doctors').select('specialty').eq('doctor_user_id', profile.id).maybeSingle();
      specialty = doc ? doc.specialty : null;
    }

    res.json({
      message: 'Login successful',
      token: authData.session.access_token,
      user: {
        id: profile.id,
        fullName: profile.full_name,
        email: profile.email,
        role: profile.role,
        specialty
      }
    });
  } catch (err) {
    console.error('Login server error:', err);
    res.status(500).json({ error: err.message });
  }
});

// =====================================================
// PROTECTED ROUTES (login token required)
// =====================================================

// Medical records - a patient can only read their own
app.get('/api/records/:patientId', requireAuth, requireRole('Patient'), async (req, res) => {
  const { patientId } = req.params;

  if (patientId !== req.user.id) {
    return res.status(403).json({ error: 'You can only view your own records.' });
  }

  const { data, error } = await supabase
    .from('medical_records')
    .select('*')
    .eq('patient_id', patientId)
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// Appointments - patients, doctors and clinics each get only their own
app.get('/api/appointments/:userId', requireAuth, async (req, res) => {
  const { userId } = req.params;

  if (userId !== req.user.id) {
    return res.status(403).json({ error: 'You can only view your own appointments.' });
  }

  // The role comes from the token's owner, not from the URL
  const role = req.user.role;

  try {
    let query = supabase
      .from('appointments')
      .select('*')
      .order('appointment_date', { ascending: true });

    if (role === 'Doctor') {
      const { data: doc } = await supabase
        .from('doctors')
        .select('id')
        .eq('doctor_user_id', userId)
        .maybeSingle();

      if (doc) query = query.eq('doctor_id', doc.id);
      else query = query.eq('doctor_id', userId);

    } else if (role === 'Clinic') {
      const { data: cl } = await supabase
        .from('clinics')
        .select('id')
        .eq('admin_user_id', userId)
        .maybeSingle();

      if (cl) query = query.eq('clinic_id', cl.id);
      else query = query.eq('clinic_id', userId);

    } else {
      query = query.eq('patient_id', userId);
    }

    const { data: appointments, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    if (!appointments || appointments.length === 0) return res.json([]);

    // Only fetch the patients that appear in these appointments
    const patientIds = [...new Set(appointments.map(a => a.patient_id))];
    const { data: profiles } = await supabase
      .from('profiles')
      .select('id, full_name, phone, email')
      .in('id', patientIds);
    const { data: doctors } = await supabase.from('doctors').select('id, name, specialty');
    const { data: clinics } = await supabase.from('clinics').select('id, name, address');

    const enriched = appointments.map(app => {
      const patient = profiles ? profiles.find(p => p.id === app.patient_id) : null;
      const doctor = doctors ? doctors.find(d => d.id === app.doctor_id) : null;
      const clinic = clinics ? clinics.find(c => c.id === app.clinic_id) : null;

      return {
        ...app,
        patientName: patient ? patient.full_name : 'Patient',
        patientPhone: patient ? patient.phone : 'N/A',
        doctorName: doctor ? doctor.name : 'Attending Doctor',
        doctorSpecialty: doctor ? doctor.specialty : 'General',
        clinicName: clinic ? clinic.name : 'Main Facility'
      };
    });

    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// List all clinics (with filters) for the patient dashboard
// Optional query params: ?city=Chennai&service=Cardiology
app.get('/api/clinics', requireAuth, async (req, res) => {
  const { city, service } = req.query;

  try {
    const { data: clinics, error: clinicErr } = await supabase
      .from('clinics')
      .select('*');
    if (clinicErr) return res.status(500).json({ error: clinicErr.message });

    const { data: doctors } = await supabase
      .from('doctors')
      .select('*');
    const allDoctors = doctors || [];

    // Doctors are matched to a clinic only if your doctors table has a clinic_id column in use.
    const hasClinicLink = allDoctors.some(d => d.clinic_id !== undefined && d.clinic_id !== null);

    let result = (clinics || []).map(clinic => {
      const clinicDoctors = hasClinicLink
        ? allDoctors.filter(d => d.clinic_id === clinic.id)
        : allDoctors;

      const services = Array.isArray(clinic.services) && clinic.services.length > 0
        ? clinic.services
        : [...new Set(clinicDoctors.map(d => d.specialty).filter(Boolean))];

      return {
        id: clinic.id,
        name: clinic.name,
        city: clinic.city,
        address: clinic.address,
        services,
        doctorsAvailable: clinicDoctors.length
      };
    });

    if (city) {
      result = result.filter(c => (c.city || '').toLowerCase() === city.toLowerCase());
    }
    if (service) {
      result = result.filter(c => c.services.some(s => s.toLowerCase() === service.toLowerCase()));
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Clinic details & doctors - a clinic admin can only see their own facility
app.get('/api/clinics/:userId/details', requireAuth, requireRole('Clinic'), async (req, res) => {
  const { userId } = req.params;

  if (userId !== req.user.id) {
    return res.status(403).json({ error: 'You can only view your own facility.' });
  }

  try {
    let { data: clinic } = await supabase
      .from('clinics')
      .select('*')
      .eq('admin_user_id', userId)
      .maybeSingle();

    if (!clinic) {
      const { data: directClinic } = await supabase
        .from('clinics')
        .select('*')
        .eq('id', userId)
        .maybeSingle();
      clinic = directClinic;
    }

    if (!clinic) {
      return res.status(404).json({ error: 'Clinic facility record not found.' });
    }

    const { data: doctors } = await supabase
      .from('doctors')
      .select('*');

    res.json({
      clinic,
      doctors: doctors || []
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Doctors of a clinic (for the booking form)
app.get('/api/clinics/:clinicId/doctors', requireAuth, async (req, res) => {
  const { clinicId } = req.params;

  try {
    const { data: doctors, error } = await supabase.from('doctors').select('*');
    if (error) return res.status(500).json({ error: error.message });

    const all = doctors || [];
    const hasClinicLink = all.some(d => d.clinic_id !== undefined && d.clinic_id !== null);
    const list = hasClinicLink ? all.filter(d => d.clinic_id === clinicId) : all;

    res.json(list.map(d => ({ id: d.id, name: d.name, specialty: d.specialty })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Already-booked time slots for a doctor on a date
app.get('/api/doctors/:doctorId/booked-slots', requireAuth, async (req, res) => {
  const { doctorId } = req.params;
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: 'date is required' });

  try {
    const { data, error } = await supabase
      .from('appointments')
      .select('time_slot')
      .eq('doctor_id', doctorId)
      .eq('appointment_date', date)
      .or('status.is.null,status.neq.Cancelled');

    if (error) return res.status(500).json({ error: error.message });
    res.json((data || []).map(a => a.time_slot));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Book an appointment - patients only, and always for themselves
app.post('/api/appointments', requireAuth, requireRole('Patient'), async (req, res) => {
  const patientId = req.user.id; // from the token, never from the request body
  const { doctorId, clinicId, date, timeSlot, notes } = req.body;

  if (!doctorId || !clinicId || !date || !timeSlot) {
    return res.status(400).json({ error: 'Please choose a doctor, date and time slot.' });
  }

  const today = new Date().toISOString().slice(0, 10);
  if (date < today) {
    return res.status(400).json({ error: 'You cannot book an appointment in the past.' });
  }

  try {
    const { data: clash, error: clashErr } = await supabase
      .from('appointments')
      .select('id')
      .eq('doctor_id', doctorId)
      .eq('appointment_date', date)
      .eq('time_slot', timeSlot)
      .or('status.is.null,status.neq.Cancelled')
      .maybeSingle();

    if (clashErr) return res.status(500).json({ error: clashErr.message });
    if (clash) {
      return res.status(409).json({ error: 'That time slot is already booked. Please pick another.' });
    }

    const { data, error } = await supabase
      .from('appointments')
      .insert([{
        patient_id: patientId,
        doctor_id: doctorId,
        clinic_id: clinicId,
        appointment_date: date,
        time_slot: timeSlot,
        symptoms_notes: notes || null
      }])
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json({ message: 'Appointment booked successfully!', appointment: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update appointment status (complete / cancel)
app.patch('/api/appointments/:id/status', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const userId = req.user.id;   // from the token
  const role = req.user.role;   // from the token

  if (!['Completed', 'Cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Status must be Completed or Cancelled.' });
  }

  try {
    const { data: appt, error } = await supabase
      .from('appointments')
      .select('*')
      .eq('id', id)
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message });
    if (!appt) return res.status(404).json({ error: 'Appointment not found.' });

    if (appt.status === 'Completed' || appt.status === 'Cancelled') {
      return res.status(400).json({ error: `This appointment is already ${appt.status.toLowerCase()}.` });
    }

    let permitted = false;

    if (role === 'Patient') {
      permitted = appt.patient_id === userId && status === 'Cancelled';
    } else if (role === 'Doctor') {
      const { data: doc } = await supabase
        .from('doctors').select('id').eq('doctor_user_id', userId).maybeSingle();
      permitted = (doc ? doc.id : userId) === appt.doctor_id;
    } else if (role === 'Clinic') {
      const { data: cl } = await supabase
        .from('clinics').select('id').eq('admin_user_id', userId).maybeSingle();
      permitted = (cl ? cl.id : userId) === appt.clinic_id;
    }

    if (!permitted) {
      return res.status(403).json({ error: 'You are not allowed to change this appointment.' });
    }

    const { data: updated, error: updErr } = await supabase
      .from('appointments')
      .update({ status })
      .eq('id', id)
      .select()
      .single();

    if (updErr) return res.status(400).json({ error: updErr.message });
    res.json({ message: `Appointment ${status.toLowerCase()}.`, appointment: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
});