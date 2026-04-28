const BLOCKED_PROTOCOLS = /^(javascript|data|vbscript|blob):/i;

async function verifyTurnstile( token, ip, secret ) {
	const res = await fetch( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify( { secret, response: token, remoteip: ip } )
	} );
	const data = await res.json();
	return data.success === true;
}

function normalizeUrl( raw ) {
	try {
		const parsed = new URL( raw );
		const host = parsed.hostname.toLowerCase();
		const path = parsed.pathname.replace( /\/+$/, '' ) + parsed.search + parsed.hash;
		return parsed.protocol + '//' + host + ( path || '/' );
	} catch( e ) {
		return null;
	}
}

function extractHostname( raw ) {
	try {
		return new URL( raw ).hostname.toLowerCase().replace( /^www\./, '' );
	} catch( e ) {
		return null;
	}
}

function generateSlug() {
	const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
	let slug = '';
	const bytes = crypto.getRandomValues( new Uint8Array( 6 ) );
	for ( const byte of bytes ) {
		slug += chars[ byte % 62 ];
	}
	return slug;
}

export async function onRequestPost( { request, env } ) {
	const headers = {
		'Content-Type': 'application/json',
		'Access-Control-Allow-Origin': '*'
	};
	try {
		const body = await request.json();
		const { url, turnstileToken } = body;
		if ( !url || typeof url !== 'string' ) {
			return new Response( JSON.stringify( { error: 'Missing URL.' } ), { status: 400, headers } );
		}
		if ( BLOCKED_PROTOCOLS.test( url.trim() ) ) {
			return new Response( JSON.stringify( { error: 'URL type not allowed.' } ), { status: 400, headers } );
		}
		const normalized = normalizeUrl( url );
		if ( !normalized ) {
			return new Response( JSON.stringify( { error: 'Invalid URL.' } ), { status: 400, headers } );
		}
		if ( !/^https?:\/\//i.test( normalized ) ) {
			return new Response( JSON.stringify( { error: 'Only http and https URLs are allowed.' } ), { status: 400, headers } );
		}
		if ( /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/i.test( normalized ) || /^https?:\/\/\[/i.test( normalized ) ) {
			return new Response( JSON.stringify( { error: 'IP address URLs are not allowed.' } ), { status: 400, headers } );
		}
		const ip = request.headers.get( 'CF-Connecting-IP' ) || '';
		const valid = await verifyTurnstile( turnstileToken, ip, env.TURNSTILE_SECRET );
		if ( !valid ) {
			return new Response( JSON.stringify( { error: 'Verification failed.' } ), { status: 403, headers } );
		}
		const hostname = extractHostname( normalized );
		if ( hostname ) {
			const cacheKey = new Request( 'https://lk0.org/blocklist.txt' );
			const cache = caches.default;
			let blocklistRes = await cache.match( cacheKey );
			if ( !blocklistRes ) {
				blocklistRes = await fetch( cacheKey );
				if ( blocklistRes.ok ) {
					const cached = new Response( blocklistRes.body, blocklistRes );
					cached.headers.set( 'Cache-Control', 'public, max-age=86400' );
					await cache.put( cacheKey, cached );
				}
			}
			if ( blocklistRes && blocklistRes.ok ) {
				const domains = new Set( ( await blocklistRes.text() ).split( '\n' ) );
				if ( domains.has( hostname ) || domains.has( 'www.' + hostname ) ) {
					return new Response( JSON.stringify( { error: 'This domain is on a known threat blocklist.' } ), { status: 400, headers } );
				}
			}
		}
		const existing = await env.ZERO_LINKS.get( 'url:' + normalized );
		if ( existing ) {
			return new Response( JSON.stringify( { slug: existing } ), { headers } );
		}
		let slug;
		for ( let i = 0; i < 5; i++ ) {
			const candidate = generateSlug();
			const taken = await env.ZERO_LINKS.get( 'slug:' + candidate );
			if ( !taken ) {
				slug = candidate;
				break;
			}
		}
		if ( !slug ) {
			return new Response( JSON.stringify( { error: 'Could not generate a unique slug. Please try again.' } ), { status: 500, headers } );
		}
		await env.ZERO_LINKS.put( 'slug:' + slug, normalized );
		await env.ZERO_LINKS.put( 'url:' + normalized, slug );
		return new Response( JSON.stringify( { slug } ), { headers } );
	} catch( e ) {
		return new Response( JSON.stringify( { error: 'Invalid request.' } ), { status: 400, headers } );
	}
}

export async function onRequestOptions() {
	return new Response( null, {
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type'
		}
	} );
}