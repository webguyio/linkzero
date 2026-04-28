const BLOCKED_PROTOCOLS = /^(javascript|data|vbscript|blob):/i;

export async function onRequestGet( { request } ) {
	const headers = {
		'Content-Type': 'application/json',
		'Access-Control-Allow-Origin': '*'
	};
	const url = new URL( request.url );
	const target = url.searchParams.get( 'url' );
	if ( !target ) {
		return new Response( JSON.stringify( { error: 'Missing URL.' } ), { status: 400, headers } );
	}
	try {
		new URL( target );
	} catch( e ) {
		return new Response( JSON.stringify( { error: 'Invalid URL.' } ), { status: 400, headers } );
	}
	if ( BLOCKED_PROTOCOLS.test( target.trim() ) ) {
		return new Response( JSON.stringify( { error: 'URL type not allowed.' } ), { status: 400, headers } );
	}
	try {
		let current = target;
		for ( let i = 0; i < 10; i++ ) {
			const res = await fetch( current, { method: 'HEAD', redirect: 'manual' } );
			const location = res.headers.get( 'location' );
			if ( ( res.status < 300 || res.status >= 400 ) || !location ) break;
			current = new URL( location, current ).href;
		}
		return new Response( JSON.stringify( { url: current } ), { headers } );
	} catch( e ) {
		return new Response( JSON.stringify( { error: 'Could not resolve URL.' } ), { status: 502, headers } );
	}
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

async function verifyTurnstile( token, ip, secret ) {
	const res = await fetch( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify( { secret, response: token, remoteip: ip } )
	} );
	const data = await res.json();
	return data.success === true;
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
		const ip = request.headers.get( 'CF-Connecting-IP' ) || '';
		const valid = await verifyTurnstile( turnstileToken, ip, env.TURNSTILE_SECRET );
		if ( !valid ) {
			return new Response( JSON.stringify( { error: 'Verification failed.' } ), { status: 403, headers } );
		}
		const hostname = extractHostname( normalized );
		if ( hostname ) {
			const res = await fetch( 'https://lk0.org/blocklist.txt' );
			if ( res.ok ) {
				const domains = ( await res.text() ).split( '\n' );
				if ( domains.includes( hostname ) || domains.includes( 'www.' + hostname ) ) {
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
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type'
		}
	} );
}