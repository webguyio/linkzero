export async function onRequestGet( { request, env, params } ) {
	const slug = params.slug;
	if ( !slug || slug.length !== 6 ) {
		return new Response( null, { status: 302, headers: { Location: '/' } } );
	}
	const url = await env.ZERO_LINKS.get( slug );
	if ( !url ) {
		return new Response( null, { status: 302, headers: { Location: '/?404=1' } } );
	}
	return new Response( null, { status: 301, headers: { Location: url } } );
}