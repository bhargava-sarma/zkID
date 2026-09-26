const path = require('path');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Service role key: RLS on `users` has no policies, so the anon key is refused.
// Safe only because this key never leaves the server.
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error(
    'Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env. ' +
      'The service role key is at Supabase Dashboard > Project Settings > API > service_role. ' +
      'The anon key will not work: RLS is enabled on `users` with no policies.'
  );
}

// Fail at startup if the anon key was pasted in by mistake.
try {
  const role = JSON.parse(
    Buffer.from(SUPABASE_SERVICE_ROLE_KEY.split('.')[1], 'base64').toString()
  ).role;
  if (role !== 'service_role') {
    throw new Error(
      `SUPABASE_SERVICE_ROLE_KEY has role "${role}", expected "service_role". ` +
        'Inserts will be refused by RLS. Check you copied the service_role key, not the anon key.'
    );
  }
} catch (err) {
  if (err.message.startsWith('SUPABASE_SERVICE_ROLE_KEY has role')) throw err;
  throw new Error('SUPABASE_SERVICE_ROLE_KEY is not a decodable JWT. Re-copy it from the dashboard.');
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

async function storeUser(name, dobEncoded, aadhaarHash, nameHash, genderCode) {
  console.log(`[SUPABASE] Inserting user — name: ${name}, hash: ${aadhaarHash.substring(0, 8)}..., gender: ${genderCode}`);

  const { data, error } = await supabase
    .from('users')
    .insert([
      {
        name,
        dob_encoded: dobEncoded,
        aadhaar_hash: aadhaarHash,
        name_hash: nameHash,
        gender_code: genderCode,
      },
    ])
    .select()
    .single();

  if (error) {
    console.log(`[SUPABASE] Insert FAILED: ${error.message}`);
    throw new Error(`Database error: ${error.message}`);
  }

  console.log(`[SUPABASE] Insert SUCCESS — user ID: ${data.id}`);
  return data;
}

async function getUserById(userId) {
  console.log(`[SUPABASE] Fetching user ID: ${userId}`);

  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('id', userId)
    .single();

  if (error) {
    console.log(`[SUPABASE] Fetch FAILED: ${error.message}`);
    throw new Error(`Database error: ${error.message}`);
  }

  console.log(`[SUPABASE] Fetch SUCCESS — user: ${data.name}`);
  return data;
}

module.exports = { storeUser, getUserById };
