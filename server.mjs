import 'dotenv/config'
import crypto from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express from 'express'
import cors from 'cors'
import { SignJWT, jwtVerify } from 'jose'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const required = ['PUBLIC_BASE_URL', 'JWT_SECRET', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']

for (const key of required) {
	if (!process.env[key]) {
		throw new Error(`Missing required environment variable: ${key}`)
	}
}

const port = Number(process.env.PORT || 8787)
const baseUrl = process.env.PUBLIC_BASE_URL.replace(/\/$/, '')
const tokenTtl = Number(process.env.TOKEN_TTL_SECONDS || 3600)
const secret = new TextEncoder().encode(process.env.JWT_SECRET)
const issuer = baseUrl
const resource = `${baseUrl}/mcp`

const perplexityRedirectUris = new Set([
	'https://www.perplexity.ai/rest/connections/oauth_callback',
	'https://www.perplexity.com/rest/connections/oauth_callback',
	'https://enterprise.perplexity.ai/rest/connections/oauth_callback',
	'https://enterprise.perplexity.com/rest/connections/oauth_callback',
	'https://staging.perplexity.ai/rest/connections/oauth_callback',
	'https://staging.perplexity.com/rest/connections/oauth_callback',
])

const authorizationCodes = new Map()
const refreshTokens = new Map()

// --- Express app + OAuth ---

const app = express()
app.set('trust proxy', true)

const allowedOrigins = new Set([
	'http://127.0.0.1:6284',
	'http://localhost:6284',
	`http://127.0.0.1:${port}`,
	`http://localhost:${port}`,
	baseUrl,
])
const corsOptions = {
	origin(origin, callback) {
		if (!origin || allowedOrigins.has(origin)) {
			return callback(null, true)
		}

		return callback(new Error(`CORS origin blocked: ${origin}`))
	},
	methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
	allowedHeaders: [
		'Accept',
		'Authorization',
		'Content-Type',
		'MCP-Protocol-Version',
		'MCP-Session-Id',
		'Ngrok-Skip-Browser-Warning',
	],
	exposedHeaders: ['WWW-Authenticate', 'MCP-Protocol-Version', 'MCP-Session-Id'],
	optionsSuccessStatus: 204,
	maxAge: 86400,
}

app.use(cors(corsOptions))
app.options('/{*splat}', cors(corsOptions))
app.use(express.urlencoded({ extended: false }))
app.use(express.json({ type: ['application/json', 'application/*+json'] }))

function randomValue(bytes = 32) {
	return crypto.randomBytes(bytes).toString('base64url')
}

function isInspectorCallback(uri) {
	try {
		const url = new URL(uri)
		const localHost = url.hostname === '127.0.0.1' || url.hostname === 'localhost'
		const inspectorPath = url.pathname === '/oauth/callback' || url.pathname === '/oauth/callback/debug'

		return url.protocol === 'http:' && localHost && /^\d+$/.test(url.port) && inspectorPath
	} catch {
		return false
	}
}

function isAllowedRedirectUri(uri) {
	return perplexityRedirectUris.has(uri) || isInspectorCallback(uri)
}

function requireAllowedRedirectUri(uri) {
	if (!isAllowedRedirectUri(uri)) {
		throw new Error(`This redirect_uri is not allowed: ${uri}`)
	}
}

function verifyPkce(verifier, challenge) {
	if (!verifier || !challenge) return false

	return crypto.createHash('sha256').update(verifier).digest('base64url') === challenge
}

async function issueAccessToken(clientId, scope = 'figma.read') {
	return new SignJWT({ scope, client_id: clientId })
		.setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
		.setIssuer(issuer)
		.setAudience(resource)
		.setSubject(process.env.ADMIN_USERNAME)
		.setIssuedAt()
		.setExpirationTime(`${tokenTtl}s`)
		.sign(secret)
}

async function verifyAccessToken(header) {
	if (!header?.startsWith('Bearer ')) {
		throw new Error('Missing bearer token')
	}

	return jwtVerify(header.slice('Bearer '.length), secret, {
		issuer,
		audience: resource,
	})
}

function sendMcpUnauthorized(res) {
	const metadataUrl = `${baseUrl}/.well-known/oauth-protected-resource/mcp`

	return res
		.status(401)
		.set('WWW-Authenticate', `Bearer resource_metadata="${metadataUrl}"`)
		.json({ error: 'unauthorized' })
}

function escapeHtml(value) {
	const entities = {
		'&': '&amp;',
		'<': '&lt;',
		'>': '&gt;',
		"'": '&#39;',
		'"': '&quot;',
	}

	return String(value).replace(/[&<>'"]/g, char => entities[char])
}

app.get('/health', (_req, res) => {
	res.json({ ok: true, service: 'figma-perplexity-mcp-gateway' })
})

app.get(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'], (_req, res) => {
	res.json({
		resource,
		authorization_servers: [issuer],
		scopes_supported: ['figma.read'],
		bearer_methods_supported: ['header'],
	})
})

app.get('/.well-known/oauth-authorization-server', (_req, res) => {
	res.json({
		issuer,
		authorization_endpoint: `${baseUrl}/authorize`,
		token_endpoint: `${baseUrl}/token`,
		response_types_supported: ['code'],
		grant_types_supported: ['authorization_code', 'refresh_token'],
		code_challenge_methods_supported: ['S256'],
		token_endpoint_auth_methods_supported: ['none'],
	})
})

app.get('/authorize', (req, res) => {
	res.type('html').send(`<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Autoryzacja</title></head>
<body>
  <main>
    <form method="post" action="/authorize">
      <input type="hidden" name="client_id" value="${escapeHtml(req.query.client_id || '')}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(req.query.redirect_uri || '')}">
      <input type="hidden" name="state" value="${escapeHtml(req.query.state || '')}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(req.query.code_challenge || '')}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(req.query.code_challenge_method || '')}">
      <input type="hidden" name="scope" value="${escapeHtml(req.query.scope || 'figma.read')}">
      <p><label>Login <input type="text" name="username" autocomplete="username" required></label></p>
      <p><label>Hasło <input type="password" name="password" autocomplete="current-password" required></label></p>
      <button type="submit">Autoryzuj</button>
    </form>
  </main>
</body>
</html>`)
})

app.post('/authorize', (req, res) => {
	const {
		username,
		password,
		client_id: clientId,
		redirect_uri: redirectUri,
		state,
		code_challenge: codeChallenge,
		code_challenge_method: codeChallengeMethod,
		scope = 'figma.read',
	} = req.body

	try {
		if (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD) {
			throw new Error('Nieprawidłowy login lub hasło.')
		}

		if (!clientId || !redirectUri) {
			throw new Error('Missing OAuth parameters.')
		}

		requireAllowedRedirectUri(redirectUri)

		if (!codeChallenge || codeChallengeMethod !== 'S256') {
			throw new Error('PKCE S256 is required.')
		}

		const code = randomValue(32)
		authorizationCodes.set(code, {
			clientId,
			redirectUri,
			codeChallenge,
			scope,
			expiresAt: Date.now() + 5 * 60 * 1000,
		})

		const callback = new URL(redirectUri)
		callback.searchParams.set('code', code)
		if (state) {
			callback.searchParams.set('state', state)
		}

		return res.redirect(callback.toString())
	} catch (error) {
		return res.status(400).type('html').send(escapeHtml(error.message))
	}
})

app.post('/token', async (req, res) => {
	try {
		const { grant_type: grantType } = req.body

		if (grantType === 'authorization_code') {
			const record = authorizationCodes.get(req.body.code)

			if (!record || record.expiresAt < Date.now()) {
				throw new Error('Invalid or expired authorization code.')
			}

			if (record.clientId !== req.body.client_id || record.redirectUri !== req.body.redirect_uri) {
				throw new Error('OAuth client mismatch.')
			}

			if (!verifyPkce(req.body.code_verifier, record.codeChallenge)) {
				throw new Error('PKCE validation failed.')
			}

			authorizationCodes.delete(req.body.code)

			const accessToken = await issueAccessToken(record.clientId, record.scope)
			const refreshToken = randomValue(48)

			refreshTokens.set(refreshToken, {
				clientId: record.clientId,
				scope: record.scope,
				expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
			})

			return res.json({
				access_token: accessToken,
				token_type: 'Bearer',
				expires_in: tokenTtl,
				refresh_token: refreshToken,
				scope: record.scope,
			})
		}

		if (grantType === 'refresh_token') {
			const record = refreshTokens.get(req.body.refresh_token)

			if (!record || record.expiresAt < Date.now() || record.clientId !== req.body.client_id) {
				throw new Error('Invalid refresh token.')
			}

			refreshTokens.delete(req.body.refresh_token)

			const accessToken = await issueAccessToken(record.clientId, record.scope)
			const refreshToken = randomValue(48)

			refreshTokens.set(refreshToken, {
				clientId: record.clientId,
				scope: record.scope,
				expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
			})

			return res.json({
				access_token: accessToken,
				token_type: 'Bearer',
				expires_in: tokenTtl,
				refresh_token: refreshToken,
				scope: record.scope,
			})
		}

		throw new Error('Unsupported grant_type.')
	} catch (error) {
		return res.status(400).json({
			error: 'invalid_grant',
			error_description: error.message,
		})
	}
})

app.listen(port, '127.0.0.1', () => {
	console.log(`Gateway local: http://127.0.0.1:${port}`)
	console.log(`OAuth issuer: ${issuer}`)
})
