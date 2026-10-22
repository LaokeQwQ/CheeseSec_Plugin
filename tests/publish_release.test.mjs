import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {publishRelease} from '../scripts/publish_release.mjs';

const bytes=value=>Buffer.from(JSON.stringify(value));
const digest=value=>createHash('sha256').update(value).digest('hex');
function fixture(){
  const previous={catalog_sequence:1,releases:[],withdrawals:[]};
  const previousBytes=bytes(previous);
  const next=bytes({...previous,catalog_sequence:2,releases:[{release_id:'official/test@0.1.0#1'}]});
  const object=(bucket,key,data)=>({bucket,key,data,size:data.length,sha256:digest(data),content_type:'application/json; charset=utf-8'});
  const catalog=object('index','catalog/index.json',next);
  const pointer=object('index','pointers/catalog.json',bytes({sequence:2,key:'indexes/catalog/seq-00000000000000000002.json',sha256:digest(next)}));
  const resource=object('resources','resources/sha256/'+digest(Buffer.from('package'))+'/test.crp',Buffer.from('package'));
  const objects=new Map([catalog,pointer,resource,object('index','indexes/catalog/seq-00000000000000000002.json',next),object('index','policy/trust-roots.json',bytes({roots:['production-public-key']}))].map(item=>[item.bucket+'/'+item.key,item]));
  const writes=[];
  function bucket(initial){
    const map=new Map(Object.entries(initial));
    let serial=0;
    return {map,writes,async get(key){if(!map.has(key))return null;const data=map.get(key);return {etag:digest(data),size:data.length,arrayBuffer:async()=>data};},async put(key,data,options){
      const headers=options.onlyIf;
      if(headers.has('if-none-match')&&map.has(key))return null;
      if(headers.has('if-match')&&(!map.has(key)||'"'+digest(map.get(key))+'"'!==headers.get('if-match')))return null;
      if(key==='catalog/index.json')assert.equal(options.customMetadata.index_sequence,'2');
      const body=Buffer.from(data);map.set(key,body);writes.push(key);return {etag:String(++serial)};
    }};
  }
  const index=bucket({'catalog/index.json':previousBytes,'pointers/catalog.json':bytes({sequence:1,key:'indexes/catalog/seq-00000000000000000001.json',sha256:digest(previousBytes)})});
  const resources=bucket({});
  return {validated:{manifest:{release_id:'official/test@0.1.0#1',catalog_sequence:2,source_commit:'a'.repeat(40)},objects,previous,previousBytes,catalog},env:{PUBLICATION_INDEX:index,PUBLIC_RESOURCES:resources},index,resources,writes};
}

test('dry run cannot contact storage',async()=>{
  const f=fixture();const receipt=await publishRelease(null,f.validated);assert.equal(receipt.applied,false);assert.equal(f.writes.length,0);
});
test('immutable resources are verified before catalog CAS and exact retry is idempotent',async()=>{
  const f=fixture();const first=await publishRelease(f.env,f.validated,{apply:true});assert.equal(first.verified,true);
  assert.ok(f.writes.indexOf('catalog/index.json')>f.writes.indexOf('indexes/catalog/seq-00000000000000000002.json'));
  assert.equal(f.writes.at(-1),'pointers/catalog.json');
  const count=f.writes.length;assert.equal((await publishRelease(f.env,f.validated,{apply:true})).verified,true);assert.equal(f.writes.length,count);
});
test('stale catalog and conflicting policy fail before any writes',async()=>{
  for(const key of ['catalog/index.json','policy/trust-roots.json']){
    const f=fixture();f.index.map.set(key,bytes({conflict:true}));await assert.rejects(publishRelease(f.env,f.validated,{apply:true}));assert.equal(f.writes.length,0);
  }
});
test('concurrent catalog changes fail CAS and preserve newer content',async()=>{
  const f=fixture();const original=f.index.put;const newer=bytes({catalog_sequence:3});
  f.index.put=async(key,data,options)=>{if(key==='catalog/index.json')f.index.map.set(key,newer);return original(key,data,options);};
  await assert.rejects(publishRelease(f.env,f.validated,{apply:true}),/CAS conflict/);assert.deepEqual(f.index.map.get('catalog/index.json'),newer);
  assert.equal(JSON.parse(f.index.map.get('pointers/catalog.json')).sequence,1);
});
test('interrupted catalog publication can repair only the previous pointer',async()=>{
  const f=fixture();f.index.map.set('catalog/index.json',f.validated.catalog.data);const result=await publishRelease(f.env,f.validated,{apply:true});assert.equal(result.verified,true);assert.equal(JSON.parse(f.index.map.get('pointers/catalog.json')).sequence,2);
});
test('a pointer inconsistent with the reviewed snapshot fails before writes',async()=>{
  const f=fixture();f.index.map.set('pointers/catalog.json',bytes({sequence:7}));await assert.rejects(publishRelease(f.env,f.validated,{apply:true}),/pointer/);assert.equal(f.writes.length,0);
});
