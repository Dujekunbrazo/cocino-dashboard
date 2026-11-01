'use strict';
// Session state is deliberately memory-only. Network details are supplied by a reviewed adapter.
(() => {
  function create({ origin, client, now = () => Date.now() }) {
    const parsed = new URL(origin);
    if (parsed.protocol !== 'https:' || !/^[a-z0-9-]+\.supabase\.co$/i.test(parsed.hostname) || parsed.username || parsed.password || parsed.port || parsed.pathname !== '/' || parsed.search || parsed.hash) throw new Error('Origen remoto no válido');
    if (!client || typeof client.signIn !== 'function' || typeof client.refresh !== 'function' || typeof client.signOut !== 'function') throw new Error('Adaptador de autenticación incompleto');
    let current = null, epoch = 0, sessionCounter = 0, controller = new AbortController(), pendingRefresh = null;
    const listeners = new Set();
    const emit = () => { const state = current ? { authenticated:true, origin:parsed.origin, userId:current.userId, scope:current.scope, expiresAt:current.expiresAt } : { authenticated:false, origin:parsed.origin }; for (const fn of listeners) fn(state); };
    function replaceEpoch(){ epoch++; controller.abort(); controller = new AbortController(); pendingRefresh = null; }
    function validate(value){ if (!value || typeof value.access_token !== 'string' || !value.access_token || typeof value.refresh_token !== 'string' || !value.refresh_token || typeof value.user?.id !== 'string' || !value.user.id || !Number.isFinite(value.expires_at) || value.expires_at*1000 <= now()) throw new Error('Sesión remota no válida'); return { access:value.access_token, refresh:value.refresh_token, userId:value.user.id, expiresAt:value.expires_at }; }
    async function signIn(email,password){ if(typeof email!=='string'||!email.trim()||typeof password!=='string'||!password) throw new Error('Introduce correo y contraseña'); replaceEpoch();current=null;emit();const version=epoch;const signal=controller.signal;const result=await client.signIn({email:email.trim(),password,signal});if(version!==epoch||signal.aborted)throw new Error('Sesión reemplazada');const next=validate(result);next.scope=`${parsed.origin}|${next.userId}|${++sessionCounter}`;current=next;emit();return {userId:next.userId,scope:next.scope}; }
    async function token(){if(!current)throw new Error('Sesión necesaria');if(current.expiresAt*1000>now()+60000)return current.access;if(!pendingRefresh){const version=epoch, signal=controller.signal, previous=current;pendingRefresh=(async()=>{try{const response=await client.refresh({refreshToken:previous.refresh,signal});if(version!==epoch||signal.aborted)throw new Error('Sesión reemplazada');const next=validate(response);if(next.userId!==previous.userId)throw new Error('Identidad de sesión no coincide');next.scope=previous.scope;current=next;emit();return next.access;}catch(e){if(version===epoch){replaceEpoch();current=null;emit()}throw e}finally{if(version===epoch)pendingRefresh=null}})()}return pendingRefresh;}
    async function signOut(){const previous=current;replaceEpoch();current=null;emit();if(previous)await client.signOut({accessToken:previous.access});}
    function state(){return current?{authenticated:true,origin:parsed.origin,userId:current.userId,scope:current.scope,expiresAt:current.expiresAt}:{authenticated:false,origin:parsed.origin};}
    return Object.freeze({signIn,signOut,token,state,subscribe(fn){listeners.add(fn);return()=>listeners.delete(fn)}});
  }
  function supabaseClient({origin,publicKey,fetcher=globalThis.fetch,now=()=>Date.now()}){
    const parsed=new URL(origin);
    if(parsed.protocol!=='https:'||!/^[a-z0-9-]+\.supabase\.co$/i.test(parsed.hostname)||parsed.username||parsed.password||parsed.port||parsed.pathname!=='/'||parsed.search||parsed.hash)throw new Error('Origen remoto no válido');
    if(typeof publicKey!=='string'||!publicKey.startsWith('sb_publishable_')||typeof fetcher!=='function')throw new Error('Configuración pública no válida');
    async function call(path,{body,accessToken,signal}={}){const headers={'apikey':publicKey,'Content-Type':'application/json'};if(accessToken)headers.Authorization=`Bearer ${accessToken}`;const result=await fetcher(parsed.origin+path,{method:'POST',headers,body:body===undefined?undefined:JSON.stringify(body),signal,credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer'});if(!result.ok)throw new Error('No se pudo completar la autenticación');if(result.status===204)return null;return result.json()}
    function normalize(v){if(!v||typeof v!=='object')throw new Error('Sesión remota no válida');const expires=Number(v.expires_at||(Math.floor(now()/1000)+Number(v.expires_in)));return {...v,expires_at:expires}}
    return Object.freeze({async signIn({email,password,signal}){return normalize(await call('/auth/v1/token?grant_type=password',{body:{email,password},signal}))},async refresh({refreshToken,signal}){return normalize(await call('/auth/v1/token?grant_type=refresh_token',{body:{refresh_token:refreshToken},signal}))},async signOut({accessToken}){await call('/auth/v1/logout?scope=local',{accessToken})}});
  }
  globalThis.BookRemoteAuth=Object.freeze({create,supabaseClient});
})();
