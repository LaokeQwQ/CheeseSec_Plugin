import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,readFile,writeFile,mkdir,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {publishBootstrap} from '../scripts/publish_bootstrap.mjs';

const sha = data => createHash('sha256').update(data).digest('hex');
async function fixture() {
  const root=await mkdtemp(join(tmpdir(),'cheesesec-bootstrap-test-'));
  const objects=[];
  async function add(key,value) {
    const data=Buffer.from(JSON.stringify(value)+'\n');
    await mkdir(dirname(join(root,key)),{recursive:true}); await writeFile(join(root,key),data);
    objects.push({key,file:key,size:data.length,sha256:sha(data),content_type:'application/json; charset=utf-8',cache_class:'short-revalidate'});
    return data;
  }
  const seq='00000000000000000001';
  const cat={api_version:'store.cheesesec.com/v1',catalog_sequence:1,releases:[],withdrawals:[]};
  const ota={api_version:'ota.cheesesec.com/v1',index_sequence:1,mode:'pull-only',releases:[]};
  const catalog=await add('catalog/index.json',cat); await add(`indexes/catalog/seq-${seq}.json`,cat);
  await add('pointers/catalog.json',{sequence:1,key:`indexes/catalog/seq-${seq}.json`,sha256:sha(catalog)});
  for(const channel of ['stable','canary','dev']) {
    const data=await add(`ota/channels/${channel}/index.json`,ota); await add(`indexes/ota/${channel}/seq-${seq}.json`,ota);
    await add(`pointers/ota/${channel}.json`,{channel,sequence:1,key:`indexes/ota/${channel}/seq-${seq}.json`,sha256:sha(data)});
  }
  const policy={api_version:'store.cheesesec.com/v1'};
  await add('policy/endpoints.json',policy); await add(`indexes/policy/seq-${seq}/endpoints.json`,policy);
  for(const [scope,names] of Object.entries({'crp-v1':['manifest','signatures'],'store-v1':['catalog','cwedp','endpoint-policy','offline-import','ota','release','revocations','sidecar-descriptor','source-registry','trust-levels','trust-roots']})) {
    for(const name of names) {
      const host=scope==='store-v1'&&name==='ota'?'ota':'store';
      const schemaPath=scope==='store-v1'?'store/v1':'crp/v1';
      const schema={$schema:'https://json-schema.org/draft/2020-12/schema',$id:`https://${host}.cheesesec.com/schema/${schemaPath}/${name}.schema.json`};
      await add(`schema/${scope}/${name}.schema.json`,schema); await add(`indexes/policy/seq-${seq}/${scope}/${name}.schema.json`,schema);
    }
  }
  const manifest={format:'cheesesec-publication-bundle-v1',source_commit:'a'.repeat(40),sequence:1,channel:'all',bootstrap_public_only:true,objects};
  async function save(){await writeFile(join(root,'bundle-manifest.json'),JSON.stringify(manifest));}
  await save();
  return {root,manifest,save,async close(){await rm(root,{recursive:true,force:true});}};
}
class Bucket {
  data=new Map(); writes=[];
  async list(){return {objects:[...this.data.keys()].map(key=>({key})),truncated:false};}
  async get(key){const data=this.data.get(key); return data===undefined?null:{size:data.length,async arrayBuffer(){return Buffer.from(data);}};}
  async put(key,data,options){
    assert.equal(options.onlyIf.get('if-none-match'),'*'); assert.equal(options.sha256,sha(data));
    this.writes.push(key); if(this.data.has(key))return null;this.data.set(key,Buffer.from(data));return {key};
  }
}
async function withFixture(fn){const f=await fixture();try{await fn(f);}finally{await f.close();}}
test('dry run fully validates without using R2',()=>withFixture(async f=>{
  const result=await publishBootstrap(undefined,f.root);assert.equal(result.applied,false);assert.equal(result.objects.length,40);
}));
test('conditional creates histories before aliases and pointers; exact resume writes nothing',()=>withFixture(async f=>{
  const bucket=new Bucket();const result=await publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true});
  assert.equal(result.verified,true);assert.equal(bucket.data.size,40);
  const firstAlias=bucket.writes.findIndex(key=>!key.startsWith('indexes/'));
  const firstPointer=bucket.writes.findIndex(key=>key.startsWith('pointers/'));
  assert(bucket.writes.slice(0,firstAlias).every(key=>key.startsWith('indexes/')));
  assert(bucket.writes.slice(firstPointer).every(key=>key.startsWith('pointers/')));
  const before=bucket.writes.length;await publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true});assert.equal(bucket.writes.length,before);
}));
test('all files validated before storage writes, including a late digest mismatch',()=>withFixture(async f=>{
  await writeFile(join(f.root,f.manifest.objects.at(-1).file),'tampered');const bucket=new Bucket();
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/digest mismatch/);assert.equal(bucket.writes.length,0);
}));
test('reject path traversal and symlink parent before writes',()=>withFixture(async f=>{
  const bucket=new Bucket();f.manifest.objects[0].file='../secret';await f.save();
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/unsafe bootstrap object/);assert.equal(bucket.writes.length,0);
  f.manifest.objects[0].file=f.manifest.objects[0].key;await f.save();
  await rm(join(f.root,'schema'),{recursive:true});await symlink('/tmp',join(f.root,'schema'));
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/symlink/);assert.equal(bucket.writes.length,0);
}));
test('read errors cannot be mistaken for empty target',()=>withFixture(async f=>{
  const bucket=new Bucket();bucket.list=async()=>{throw new Error('storage unavailable');};
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/storage unavailable/);assert.equal(bucket.writes.length,0);
}));
test('non-bootstrap bucket and conflicting object rejected before writes',()=>withFixture(async f=>{
  const bucket=new Bucket();bucket.data.set('unrelated.json',Buffer.from('{}'));
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/bootstrap target/);assert.equal(bucket.writes.length,0);
  bucket.data.clear();bucket.data.set('catalog/index.json',Buffer.from('{}'));
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/conflict/);assert.equal(bucket.writes.length,0);
}));
test('concurrent conflicting create cannot overwrite history or publish aliases',()=>withFixture(async f=>{
  const bucket=new Bucket();const put=bucket.put.bind(bucket);let raced=false;
  bucket.put=async(key,data,options)=>{if(!raced){raced=true;bucket.data.set(key,Buffer.from('newer publisher'));}return put(key,data,options);};
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/conditional create conflict/);
  assert.equal(bucket.writes.length,1);assert(bucket.writes[0].startsWith('indexes/'));assert.equal(bucket.data.get(bucket.writes[0]).toString(),'newer publisher');
}));
test('nonempty releases, demo roots, and unsafe sequences rejected',()=>withFixture(async f=>{
  const bucket=new Bucket();const item=f.manifest.objects.find(x=>x.key==='catalog/index.json');
  const data=Buffer.from(JSON.stringify({api_version:'store.cheesesec.com/v1',catalog_sequence:1,releases:[{release_id:'demo'}],withdrawals:[]}));
  await writeFile(join(f.root,item.file),data);item.size=data.length;item.sha256=sha(data);await f.save();
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/catalog must be empty/);assert.equal(bucket.writes.length,0);
  f.manifest.sequence=Number.MAX_SAFE_INTEGER+1;await f.save();
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/sequence/);
}));
test('demo trust keys not accepted even if manifest digest matches',()=>withFixture(async f=>{
  const bucket=new Bucket();const item=f.manifest.objects.find(x=>x.key==='policy/endpoints.json');
  const data=Buffer.from(JSON.stringify({api_version:'store.cheesesec.com/v1',roots:['official-demo-1']}));
  await writeFile(join(f.root,item.file),data);item.size=data.length;item.sha256=sha(data);await f.save();
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true}),/demo trust material/);assert.equal(bucket.writes.length,0);
}));
test('existing receipt is rejected before storage writes',()=>withFixture(async f=>{
  const bucket=new Bucket();
  await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true,receiptPath:join(f.root,'bundle-manifest.json')}),/receipt must be outside/);
  const receipt=join(tmpdir(),`cheesesec-receipt-${process.pid}-${Date.now()}.json`);
  try {
    await writeFile(receipt,'retain receipt');
    await assert.rejects(publishBootstrap({PUBLICATION_INDEX:bucket},f.root,{apply:true,receiptPath:receipt}),/receipt destination already exists/);
    assert.equal(await readFile(receipt,'utf8'),'retain receipt');assert.equal(bucket.writes.length,0);
  } finally {await rm(receipt,{force:true});}
}));
