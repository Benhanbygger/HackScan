'use strict';
const panel=document.querySelector('#administration'), csrf=panel.dataset.csrf;
const msg=document.querySelector('#admin-message');
async function adminApi(action,values) {
 const response=await fetch('index.php?api='+action,{method:values?'POST':'GET',credentials:'same-origin',headers:values?{'X-CSRF-Token':csrf}:{},body:values?new URLSearchParams(values):undefined});
 if(response.status===401){location.href='index.php';throw Error('Log ind igen');}
 const data=await response.json(); if(!response.ok)throw Error(data.error||'Handlingen kunne ikke gennemføres');return data;
}
function option(role,text){return new Option(text,role);}
async function loadUsers(){
 const data=await adminApi('users'); const list=document.querySelector('#user-list');list.replaceChildren();
 for(const user of data.users){
  const row=document.createElement('form');row.className='user-row';
  const name=document.createElement('strong');name.textContent=user.username;
  const role=document.createElement('select');role.setAttribute('aria-label','Rolle for '+user.username);role.append(option('admin','Administrator'),option('user','Bruger'),option('viewer','Læser'));role.value=user.role;
  const label=document.createElement('label');label.className='active-checkbox';const active=document.createElement('input');active.type='checkbox';active.checked=!!user.active;label.append(active,document.createTextNode('Aktiv'));
  const password=document.createElement('input');password.type='password';password.autocomplete='new-password';password.placeholder='Ny adgangskode (valgfri)';password.minLength=14;password.maxLength=72;password.setAttribute('aria-label','Nulstil adgangskode for '+user.username);
  const save=document.createElement('button');save.className='button secondary';save.textContent='Gem';
  if(user.id===Number(panel.dataset.self)){role.disabled=true;active.disabled=true;}
  row.append(name,role,label,password,save);
  row.onsubmit=async event=>{event.preventDefault();save.disabled=true;try{const result=await adminApi('user_update',{id:user.id,role:role.value,active:active.checked?'1':'0',password:password.value});password.value='';if(result.reauthenticate){location.href='index.php';return;}msg.textContent='Brugeren er opdateret. Tidligere sessioner er afsluttet.';await loadUsers();}catch(e){msg.textContent=e.message;}finally{save.disabled=false;}};
  list.append(row);
 }
 const audit=document.querySelector('#audit-list');audit.replaceChildren();
 for(const event of data.audit){const p=document.createElement('p');p.textContent=`${event.created_at} UTC · ${event.actor_name||'Administrator'} → ${event.subject_name||'Bruger'} · ${event.event}`;audit.append(p);}
}
document.querySelector('#create-user').onsubmit=async event=>{event.preventDefault();const form=event.target;const button=form.querySelector('button');button.disabled=true;try{await adminApi('user_create',{username:document.querySelector('#new-username').value,password:document.querySelector('#new-password').value,role:document.querySelector('#new-role').value});form.reset();msg.textContent='Brugeren er oprettet. Adgangskoden vises eller gemmes ikke i klartekst.';await loadUsers();}catch(e){msg.textContent=e.message;}finally{button.disabled=false;}};
loadUsers().catch(e=>msg.textContent=e.message);

document.querySelector('#clear-results').onclick=async event=>{
 if(!window.confirm('Ryd alle resultater? Dette stopper scanningen og sletter alle resultater, sikkerhedsrapporter og historik for alle brugere. Handlingen kan ikke fortrydes.'))return;
 const button=event.currentTarget;button.disabled=true;
 try{await adminApi('clear_results',{confirmation:'RYD ALLE RESULTATER'});msg.textContent='Alle resultater er ryddet. Brugere og indstillinger er bevaret.';await loadUsers();}
 catch(e){msg.textContent=e.message;}finally{button.disabled=false;}
};
