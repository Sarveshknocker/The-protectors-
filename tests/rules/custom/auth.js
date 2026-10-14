// Corpus for a project-specific rule declared in .protectors-rules.json.
// ruleid: custom.legacy-auth-header
const user = lookup(req.headers['x-api-auth']);
// ok: custom.legacy-auth-header
const user2 = req.session.user;
