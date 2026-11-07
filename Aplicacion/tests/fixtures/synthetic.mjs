// Synthetic records for reproducible tests. No operational log data is included.
export function event(overrides={}){
 return {Log_ID:'SYN-001',Timestamp:'2025-01-15 08:00:00',Hostname:'AUTH-SYN',Event_ID:4625,User:'user-a',Source_IP:'192.0.2.10',Destination:'-',Log_Source:'Synthetic',Event_Description:'Authentication failure',Process_CommandLine:'',Result:'Failure',Severity:'Informational',...overrides};
}
export const failedBurst=Array.from({length:5},(_,i)=>event({Log_ID:`SYN-A${i}`,Timestamp:`2025-01-15 08:0${i}:00`,User:`user-${i%3}`}));
const records=[
 ...failedBurst,
 event({Log_ID:'SYN-A5',Timestamp:'2025-01-15 08:05:00',Event_ID:4624,User:'user-0',Result:'Success'}),
 ...Array.from({length:4},(_,i)=>event({Log_ID:`SYN-R${i}`,Timestamp:`2025-01-15 09:0${i}:00`,Hostname:'REMOTE-SYN',User:'admin-syn',Source_IP:'192.0.2.20',Event_Description:'RDP; LogonType=10'})),
 event({Log_ID:'SYN-R4',Timestamp:'2025-01-15 09:04:00',Event_ID:4624,Hostname:'REMOTE-SYN',User:'admin-syn',Source_IP:'192.0.2.20',Event_Description:'LogonType=10',Result:'Success'}),
 event({Log_ID:'SYN-R5',Timestamp:'2025-01-15 09:05:00',Event_ID:4688,Hostname:'REMOTE-SYN',User:'admin-syn',Source_IP:'192.0.2.20',Process_CommandLine:'powershell.exe -EncodedCommand SYNTHETIC',Result:'Success'}),
 event({Log_ID:'SYN-R6',Timestamp:'2025-01-15 09:06:00',Event_ID:4624,Hostname:'FILES-SYN',User:'admin-syn',Source_IP:'10.20.0.8',Event_Description:'LogonType=3; source=REMOTE-SYN',Result:'Success'}),
 event({Log_ID:'SYN-R7',Timestamp:'2025-01-15 09:07:00',Event_ID:5145,Hostname:'FILES-SYN',User:'admin-syn',Source_IP:'10.20.0.8',Event_Description:'Share access',Result:'Success'}),
 event({Log_ID:'SYN-V0',Timestamp:'2025-01-15 10:00:00',Event_ID:4688,Hostname:'BACKUP-SYN',User:'operator-syn',Source_IP:'10.20.0.9',Process_CommandLine:'vssadmin.exe delete shadows /all /quiet',Result:'Success'}),
 event({Log_ID:'SYN-T0',Timestamp:'2025-01-15 11:00:00',Event_ID:4688,Hostname:'TRANSFER-SYN',User:'transfer-syn',Source_IP:'10.20.0.10',Process_CommandLine:'7z.exe a C:\\Temp\\synthetic.7z C:\\Synthetic',Result:'Success'}),
 ...Array.from({length:3},(_,i)=>event({Log_ID:`SYN-T${i+1}`,Timestamp:`2025-01-15 11:0${i+1}:00`,Event_ID:'PROXY_ACCESS',Hostname:'TRANSFER-SYN',User:'transfer-syn',Source_IP:'10.20.0.10',Destination:'198.51.100.10:443',Event_Description:'HTTPS POST outbound; bytes_out=4000000',Result:'Allowed'})),
 event({Log_ID:'SYN-P0',Timestamp:'2025-01-15 12:00:00',Event_ID:4698,Hostname:'TASK-SYN',User:'service-syn',Source_IP:'10.20.0.11',Process_CommandLine:'C:\\ProgramData\\Synthetic\\worker.exe',Result:'Success'}),
 event({Log_ID:'SYN-P1',Timestamp:'2025-01-15 12:01:00',Event_ID:4688,Hostname:'TASK-SYN',User:'service-syn',Source_IP:'10.20.0.11',Process_CommandLine:'C:\\ProgramData\\Synthetic\\worker.exe',Result:'Success'}),
 event({Log_ID:'SYN-W0',Timestamp:'2025-01-15 13:00:00',Event_ID:'HTTP_ACCESS',Hostname:'WEB-SYN',User:'-',Source_IP:'192.0.2.30',Process_CommandLine:'GET /synthetic.aspx?cmd=whoami',Result:'200'}),
 event({Log_ID:'SYN-W1',Timestamp:'2025-01-15 13:01:00',Event_ID:4688,Hostname:'WEB-SYN',User:'IIS APPPOOL\\Synthetic',Source_IP:'192.0.2.30',Process_CommandLine:'cmd.exe /c whoami',Result:'Success'}),
];
export const rows=records.map((r,i)=>({...r,sourceRow:i+2,sourceSheet:'Synthetic'}));
