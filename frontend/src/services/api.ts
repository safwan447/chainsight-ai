const API='http://localhost:8000/api';
export async function get<T>(path:string):Promise<T>{const r=await fetch(API+path);if(!r.ok)throw new Error(await r.text());return r.json()}
export async function upload(file:File){const form=new FormData();form.append('file',file);const r=await fetch(API+'/ingest/upload',{method:'POST',body:form});if(!r.ok)throw new Error(await r.text());return r.json()}
export async function process(filename?:string,sourcePath?:string){const query=sourcePath?'?source_path='+encodeURIComponent(sourcePath):filename?'?filename='+encodeURIComponent(filename):'';const r=await fetch(API+'/ingest/process'+query,{method:'POST'});if(!r.ok)throw new Error(await r.text());return r.json()}
export {API};
