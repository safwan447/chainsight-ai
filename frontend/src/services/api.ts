const API='http://localhost:8000/api';
export async function get<T>(path:string):Promise<T>{const r=await fetch(API+path);if(!r.ok)throw new Error(await r.text());return r.json()}
export async function upload(file:File){const form=new FormData();form.append('file',file);const r=await fetch(API+'/ingest/upload',{method:'POST',body:form});if(!r.ok)throw new Error(await r.text());return r.json()}
export async function process(filename?:string,sourcePath?:string){const query=sourcePath?'?source_path='+encodeURIComponent(sourcePath)+'&background=true':filename?'?filename='+encodeURIComponent(filename)+'&background=true':'?background=true';const r=await fetch(API+'/ingest/process'+query,{method:'POST'});if(!r.ok)throw new Error(await r.text());return r.json()}

export async function waitForIngestion(jobId?:string,onUpdate?:(status:any)=>void){let failures=0;while(true){try{const status=await get<any>('/ingest/status');failures=0;if(!jobId||status.job_id===jobId){onUpdate?.(status);if(['complete','error','cancelled'].includes(status.state))return status;}}catch(error){failures+=1;if(failures>=5)throw error;}await new Promise(resolve=>setTimeout(resolve,1500));}}
export {API};
