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

export async function onRequestPost( { request, env } ) {
	const headers = {
		'Content-Type': 'application/json',
		'Access-Control-Allow-Origin': '*'
	};
	try {
		const body = await request.json();
		const { url: target, turnstileToken } = body;
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
		const ip = request.headers.get( 'CF-Connecting-IP' ) || '';
		const valid = await verifyTurnstile( turnstileToken, ip, env.TURNSTILE_SECRET );
		if ( !valid ) {
			return new Response( JSON.stringify( { error: 'Verification failed.' } ), { status: 403, headers } );
		}
		let current = target;
		for ( let i = 0; i < 10; i++ ) {
			const parsed = new URL( current );
			if ( parsed.hostname === 'lk0.org' ) {
				const slug = parsed.pathname.replace( '/', '' );
				const resolved = await env.ZERO_LINKS.get( 'slug:' + slug );
				if ( resolved ) {
					current = resolved;
				}
				break;
			}
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

export async function onRequestOptions() {
	return new Response( null, {
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type'
		}
	} );
}