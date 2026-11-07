let generator;
let engine='wasm';
self.onmessage=async({data})=>{
 try{
  if(data.type==='load'){
   const {pipeline,env}=await import('./vendor/transformers.min.js');
   env.allowLocalModels=false;
   env.backends.onnx.wasm.numThreads=1;
   env.backends.onnx.wasm.proxy=false;
   const adapter=await self.navigator?.gpu?.requestAdapter?.().catch(()=>null);
   engine=adapter?'webgpu':'wasm';
   self.postMessage({type:'status',text:`Preparando IA local (${engine==='webgpu'?'GPU':'CPU'}). La primera descarga puede tardar varios minutos.`});
   const options={dtype:'q4',device:engine,progress_callback:p=>{if(p.status==='progress')self.postMessage({type:'progress',progress:p.progress,file:p.file});}};
   try{generator=await pipeline('text-generation','onnx-community/Qwen2.5-0.5B-Instruct',options);}catch(error){
    if(engine!=='webgpu')throw error; const gpuError=error.message||String(error); engine='wasm';self.postMessage({type:'status',text:'GPU no disponible para este modelo. Preparando alternativa en CPU.'});
    try{generator=await pipeline('text-generation','onnx-community/Qwen2.5-0.5B-Instruct',{...options,dtype:'q4',device:'wasm'});}catch(cpuError){throw new Error(`No se pudo cargar el modelo. GPU: ${gpuError}. CPU: ${cpuError.message||String(cpuError)}`);}
   }
   self.postMessage({type:'ready',engine});
  }
  if(data.type==='generate'){
   if(!generator)throw new Error('Primero activa el modelo local.');
   const result=await generator(data.messages,{max_new_tokens:64,do_sample:false,repetition_penalty:1.12});
   const value=result[0].generated_text;
   self.postMessage({type:'result',text:typeof value==='string'?value:value.at(-1).content});
  }
 }catch(error){self.postMessage({type:'error',text:error.message||String(error)});}
};
