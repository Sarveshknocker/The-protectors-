// Rule corpus (secrets). Values are generated at test time from {{FAKE:...}} placeholders.
// ruleid: secret.aws-access-key
const v_aws_access_key = "{{FAKE:aws}}";
// ruleid: secret.github-token
const v_github_token = "{{FAKE:github}}";
// ruleid: secret.gitlab-token
const v_gitlab_token = "{{FAKE:gitlab}}";
// ruleid: secret.slack-token
const v_slack_token = "{{FAKE:slack}}";
// ruleid: secret.slack-webhook
const v_slack_webhook = "{{FAKE:slack-webhook}}";
// ruleid: secret.stripe-live
const v_stripe_live = "{{FAKE:stripe}}";
// ruleid: secret.google-api-key
const v_google_api_key = "{{FAKE:google}}";
// ruleid: secret.openai-key
const v_openai_key = "{{FAKE:openai}}";
// ruleid: secret.anthropic-key
const v_anthropic_key = "{{FAKE:anthropic}}";
// ruleid: secret.twilio
const v_twilio = "{{FAKE:twilio}}";
// ruleid: secret.sendgrid
const v_sendgrid = "{{FAKE:sendgrid}}";
// ruleid: secret.npm-token
const v_npm_token = "{{FAKE:npm}}";
// ruleid: secret.razorpay
const v_razorpay = "{{FAKE:razorpay}}";
// ruleid: secret.huggingface
const v_huggingface = "{{FAKE:huggingface}}";
// ruleid: secret.shopify
const v_shopify = "{{FAKE:shopify}}";
// ruleid: secret.digitalocean
const v_digitalocean = "{{FAKE:digitalocean}}";
// ruleid: secret.pypi
const v_pypi = "{{FAKE:pypi}}";
// ruleid: secret.postman
const v_postman = "{{FAKE:postman}}";
// ruleid: secret.atlassian
const v_atlassian = "{{FAKE:atlassian}}";
// ruleid: secret.telegram-bot
const v_telegram_bot = "{{FAKE:telegram}}";
// ruleid: secret.discord-webhook
const v_discord_webhook = "{{FAKE:discord}}";
// ruleid: secret.azure-storage
const v_azure_storage = "{{FAKE:azure}}";
// ruleid: secret.groq
const v_groq = "{{FAKE:groq}}";
// ruleid: secret.supabase-pat
const v_supabase_pat = "{{FAKE:supabase}}";
// ruleid: secret.linear
const v_linear = "{{FAKE:linear}}";
// ruleid: secret.doppler
const v_doppler = "{{FAKE:doppler}}";
// ruleid: secret.vault
const v_vault = "{{FAKE:vault}}";
// ruleid: secret.databricks
const v_databricks = "{{FAKE:databricks}}";
// ruleid: secret.dockerhub
const v_dockerhub = "{{FAKE:dockerhub}}";
// ruleid: secret.age
const v_age = "{{FAKE:age}}";
// ruleid: secret.private-key
const v_private_key = "{{FAKE:pem}}";
// ruleid: secret.db-url-with-password
const v_db_url_with_password = "{{FAKE:dburl}}";
// ruleid: secret.jwt
const v_jwt = "{{FAKE:jwt}}";
// ruleid: secret.aws-secret-key
const awsConf = "aws_secret_access_key = {{FAKE:aws-secret}}";
// ruleid: secret.generic-assignment
const api_key = "{{FAKE:generic}}";
// ok: secret.generic-assignment
const api_key2 = "your-api-key-here";
// ok: secret.generic-assignment
const password = "aaaaaaaaaaaaaaaa";
// ok: secret.generic-assignment
const client_secret = process.env.CLIENT_SECRET;
// ok: secret.db-url-with-password
const local = "postgres://user:pass@localhost:5432/dev";
