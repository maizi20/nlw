(g=>{
  g._request=g._fetch=g.fetch,g.onfetch=e=>e.respondWith(_request(e.request,e))
  ,g.param||(g.param=new URL(location).searchParams)
  ,g.oninstall=e=>e.waitUntil(done)
  ,g.ccwdata=new class CCWData{
    constructor(keys,c){
      this.keys=new Map(keys&&keys.map(e=>[e.id,e])),this.keyReady=Promise.all(keys&&keys.map(
        k=>c.importKey('jwk',{kty:'RSA',n:k.k,e:'AQAB'},{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},!0,['verify'])
        .then(key=>k.key=key)
      )).then(()=>this.keys)
    }list(p,t,k,s){
      return new Request('https://community-web-cloud-database.ccw.site/cloud_variable/list',{
        headers:{
          accept:'application/json, text/plain, *\x2f*',
          'accept-language':'zh-CN,zh;q=0.9',
          'content-type':'application/json',
        },method:'POST',mode:'cors',credentials:'omit',signal:s
        ,body:JSON.stringify({accessKey:p,primaryKey:p,secondaryKeys:t,filterKeys:k||[]})
      })
    }async file(o,c){
      var keys=await this.keyReady
      ,raw=n=>new Uint8Array(n.length).map((a,i)=>n.charCodeAt(i))
      ,{s,h}=o,{0:k,1:s}=s.split(','),s=raw(atob(s)),h=raw(atob(h)),e=keys.get(k)
      ,n=e&&c&&e.key instanceof CryptoKey&&await c.verify('RSASSA-PKCS1-v1_5',e.key,s,h)&&e.lv|0||0
      ,h=JSON.parse(new TextDecoder().decode(h)),b64='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.split('')
      ;for(var i=0,d,t='';d=o[''+b64[i>>6]+b64[i&63]];++i)t+=atob(d)
      ;t=raw(t),n=n&&c&&atob(h['content-hash']||'')===Array.from(new Uint8Array(await c.digest('SHA-256',t)),a=>String.fromCharCode(a)).join('')|0&&n
      ;return{head:h,body:t,level:n,key:k}
    }
  }([
    {id:'AAAAAAAB',a:'admin',lv:3,k:'sSvHgbkz-FUpOf6e4SOvEsRUX5p3yz3RZdydOukihK18WGDOjVwPZg89XKWrdIKB2BbCNKEW92yz-Fe9A-hNBO2kSg1Apeun8IEknwScGhf2xKYdP6PK0Q6L3cycMiQffRgebizafA6dmnKkr7CGBTD3ouh9sOY_RHlwMTMSfJs'}
  ],crypto.subtle)
  ;var src='/nlw/init/'+param.get('init')+'.js',done=fetch(ccwdata.list('661bdd5701ae7d4c2b5dadc9',[src]))
  .then(r=>r.json()).then(o=>ccwdata.file(o.body[src],crypto.subtle))
  .then(o=>{
    if(o.level>1)return new TextDecoder().decode(o.body);
    throw new Error('Signal not match.');
  }).then(g.callback||eval,g.alert)
})(self)
