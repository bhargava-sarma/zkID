const { createClient } = require('@supabase/supabase-js');
require('dotenv').config({ path: '../.env' });

// =============================================================================
// Client
// =============================================================================
//
// Uses the SERVICE ROLE key, not the anon key. RLS is enabled on `users` with no
// policies, so the anon key is refused on insert:
//
//   code 42501: new row violates row-level security policy for table "users"
//
// The service role key bypasses RLS. That is only safe because this key never
// leaves the server: the frontend has no Supabase client and no
// @supabase/supabase-js dependency, so all database traffic is
// browser -> this backend -> Supabase. If a Supabase client is ever added to
// frontend/, this decision has to be revisited - a service role key shipped to a
// browser hands every visitor full table access.
//
// The anon key stays locked down and unused. See .env.example.

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error(
    'Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env. ' +
      'The service role key is at Supabase Dashboard > Project Settings > API > service_role. ' +
      'The anon key will not work: RLS is enabled on `users` with no policies.'
  );
}

// Catch the most likely misconfiguration - pasting the anon key into the service
// role slot - at startup rather than as a confusing 42501 on the first write.
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
  // No session persistence or token refresh: this is a server-side client using
  // a static key, not a logged-in user.
  auth: { persistSession: false, autoRefreshToken: false },
});

async function storeUser(name, dobEncoded, aadhaarHash, nameHash, genderCode) {
  console.log(`[SUPABASE] Inserting user — name: ${name}, hash: ${aadhaarHash.substring(0, 8)}..., gender: ${genderCode}`);

  const insertData = {
    name,
    // Column renamed from dob_days as part of retiring days-since-epoch.
    // Requires the migration in README.md to have been run.
    dob_encoded: dobEncoded,
    aadhaar_hash: aadhaarHash,
  };

  // Only include new fields if they have values (for backward compatibility)
  if (nameHash) insertData.name_hash = nameHash;
  if (genderCode !== undefined && genderCode !== null) insertData.gender_code = genderCode;

  const { data, error } = await supabase
    .from('users')
    .insert([insertData])
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
