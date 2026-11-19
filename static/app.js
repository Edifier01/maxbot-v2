const names={overview:'Обзор',groups:'Группы, номера и IP',messages:'Пул сообщений',settings:'Настройки',log:'Журнал'};let csrf=(document.cookie.match(/(?:^|; )owner_csrf=([^;]*)/)||[])[1]||'';let current='overview';let viewGeneration=0;let appTimezone='Europe/Moscow';
const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function humanError(value){const s=String(value||'');return ({network_error:'Нет связи с панелью. Проверьте интернет и повторите попытку.',authentication_required:'Войдите в панель.',invalid_credentials:'Неверный логин или пароль.',invalid_request:'Проверьте введённые данные и ограничения формы.',invalid_max_invite_link:'Укажите действующую ссылку приглашения MAX вида https://max.ru/join/…',no_connected_account_for_verification:'Нужен авторизованный номер MAX с доступным IP VDS.',account_assignment_changed_during_verification:'Назначение IP аккаунта изменилось. Запустите проверку ещё раз.',group_invite_changed_during_verification:'Ссылка группы изменилась. Запустите проверку ещё раз.',group_resolution_failed:'Не удалось проверить ссылку MAX. Проверьте ссылку, аккаунт и IP.',ip_assignment_required:'На VDS нет включённого IP для MAX. Сообщите владельцу.',ip_assignment_unavailable:'Назначенный IP недоступен. Владелец может выбрать другой.',ip_assignment_changed:'IP аккаунта изменился. Подключаемся заново.',ip_unavailable:'IP недоступен или выключен на VDS.',invalid_send_proxy:'Нужен внешний адрес вида socks5://логин:пароль@хост:порт или socks5://хост:порт.',send_proxy_required:'Для этого IP нужен проверенный и включённый прокси отправки.',send_proxy_unavailable:'Назначенный прокси приостановлен или выключен. Проверьте его или выберите другой вручную.',send_proxy_check_required:'Сначала успешно проверьте соединение через этот прокси.',send_proxy_check_in_progress:'Проверка SOCKS5 уже выполняется. Дождитесь её завершения.',send_proxy_not_found:'Прокси не найден в этом пуле.',ip_not_found:'IP VDS не найден.',send_proxy_changed:'Прокси был переназначен.',send_proxy_config_invalid:'Данные прокси не удалось прочитать. Добавьте его заново и переназначьте аккаунт.',send_proxy_account_unavailable:'Нужен авторизованный аккаунт с назначенным IP.',account_or_ip_not_found:'Аккаунт или IP не найден.',account_not_found:'Номер не найден.',account_deletion_unavailable:'Не удалось безопасно начать удаление номера.',account_deletion_incomplete:'Удаление не завершено. Повторите действие позже.',operation_reconciliation_required:'Сначала вручную сверьте неопределённую отправку в журнале.',max_password_required_on_active_session:'MAX требует пароль для входа при активной сессии. Установите пароль в официальном приложении MAX и повторите попытку.',saved_session_rejected:'MAX отклонил сохранённую сессию. При ручной повторной попытке будет создано новое поколение.',account_reauthentication_required:'Сессия MAX отклонена. Владелец должен вручную переподключить номер.',reauthentication_started:'Эта попытка членства заменена новым ручным входом для номера.',auth_session_not_saved:'Не удалось подтвердить сохранение авторизованной сессии.',invite_unavailable:'Ссылка истекла, отозвана или достигла лимита подключений.',onboarding_in_progress:'Подключение этого номера уже выполняется.',onboarding_session_unavailable:'Попытка подключения больше недоступна. Начните её заново.',phone_already_exists:'Этот номер уже подключён или назначен другой группе.',session_save_failed:'Не удалось сохранить сессию MAX. Проверьте настройки данных и ключ.',invalid_schedule_settings:'Проверьте часовой пояс и окна отправки.',invalid_delay_range:'Пауза «до» должна быть не меньше паузы «от».',run_stopped:'Работа остановлена.',outside_send_window:'Сейчас вне разрешённого окна отправки.',account_not_active:'Аккаунту нужно подтвердить членство в группе.',destination_unverified:'Назначение группы ещё не проверено.',weekly_limit_reached:'Для номера уже есть принятое сообщение на этой неделе.',chat_busy:'В этот чат уже идёт отправка.',chat_queue_turn:'Ожидает своей очереди в общем чате.',chat_pause:'Действует пауза между отправками в этот чат.',chat_daily_limit_reached:'Дневной лимит сообщений для этого чата исчерпан.'})[s]||'Не удалось выполнить действие. Проверьте данные и повторите попытку.'}
async function api(path,opts={}){const headers={'Content-Type':'application/json',...(opts.headers||{})};if(csrf)headers['X-CSRF-Token']=csrf;let r;try{r=await fetch(path,{...opts,headers,credentials:'same-origin',cache:opts.cache||'no-store'})}catch{throw Error(humanError('network_error'))}if(r.status===401){showLogin();throw Error('Сессия завершена')}const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(humanError(d.detail));return d}
function notice(text,error=false){$('#notice').textContent=text;$('#notice').className=error?'notice danger':'notice';setTimeout(()=>$('#notice').textContent='',5000)}
function showLogin(){ $('#app').hidden=true;$('#login').hidden=false }
function showApp(){ $('#login').hidden=true;$('#app').hidden=false;loadView(current);updateRun() }
$('#login-form').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget,button=form.querySelector('button');button.disabled=true;const fd=new FormData(form);try{const d=await api('/api/auth/login',{method:'POST',body:JSON.stringify(Object.fromEntries(fd))});csrf=d.csrf_token;showApp()}catch(x){$('#login-error').textContent=humanError(x.message)}finally{button.disabled=false}});
document.querySelectorAll('nav [data-view]').forEach(b=>b.onclick=()=>{current=b.dataset.view;document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('active',x===b));loadView(current)});
$('#logout').onclick=async event=>{const button=event.currentTarget;button.disabled=true;try{await api('/api/auth/logout',{method:'POST',body:'{}'})}finally{csrf='';showLogin();button.disabled=false}};
$('#run-toggle').onclick=async event=>{const button=event.currentTarget;button.disabled=true;try{const stop=button.dataset.stop==='1';await api(stop?'/api/run/start':'/api/run/stop',{method:'POST',body:'{}'});await updateRun()}catch(error){notice(error.message,true)}finally{button.disabled=false}};
async function updateRun(){try{const d=await api('/api/overview');const stopped=d.stopped;$('#run-state').textContent=stopped?'Остановлено':'Работа сейчас включена';$('#run-state').title=d.run_wait_reason||'';$('#run-state').classList.toggle('off',stopped);$('#run-toggle').textContent=stopped?'Запустить':'Остановить';$('#run-toggle').dataset.stop=stopped?'1':'0'}catch{}}
async function loadView(view){const generation=++viewGeneration;$('#title').textContent=names[view];try{if(view==='overview')await overview(generation);if(view==='groups')await groups(generation);if(view==='messages')await messages(generation);if(view==='settings')await settings(generation);if(view==='log')await logs(generation)}catch(e){if(generation===viewGeneration)notice(e.message,true)}}
function formatDate(value){if(!value)return '—';try{return new Intl.DateTimeFormat('ru-RU',{dateStyle:'medium',timeStyle:'short',timeZone:appTimezone}).format(new Date(value))}catch{return String(value)}}
function formatDay(value){if(!value)return '—';try{return new Intl.DateTimeFormat('ru-RU',{dateStyle:'medium',timeZone:'UTC'}).format(new Date(`${value}T12:00:00Z`))}catch{return String(value)}}
function accountStatus(value){return ({active:'подключён',needs_membership:'нужно подтвердить вступление',pending:'не подключён',starting:'подключение запускается',requesting_code:'запрашиваем код',waiting_code:'ожидает код',verifying_code:'проверяем код',waiting_password:'ожидает пароль',verifying_password:'проверяем пароль',waiting_membership:'ожидает вступления',completed:'завершено',failed:'ошибка',expired:'истекло',cancelled:'отменено',queued:'запланирован',in_flight:'выполняется',accepted:'отправлен',unknown:'неизвестный результат · нужна проверка',blocked:'приостановлен',missed:'пропущен',attempt:'попытка подключения',authentication:'проверка входа',connect:'соединение с MAX',handshake:'рукопожатие MAX',request_code:'запрос кода в MAX',otp:'проверка кода',two_factor:'проверка пароля',login:'вход в MAX',profile:'загрузка профиля',resolve_group:'проверка ссылки MAX',join_group:'вступление в группу',check_membership:'проверка членства',membership:'проверка членства',session_cleanup:'удаление файлов сессии',wait_code_input:'ожидание ввода кода',wait_password_input:'ожидание ввода пароля',group_created:'создана группа',group_destination_changed:'изменена ссылка группы',group_updated:'обновлена группа',group_enabled:'группа запущена',group_disabled:'группа остановлена',group_destination_verified:'группа проверена',ip_reassigned:'переназначен IP',account_deleted:'номер и сессии удалены',operation_manually_resolved:'операция сверена вручную',chat_dispatch_policy_updated:'правила отправки в чат обновлены'})[value]||value||'—'}
function eventDetail(row){const results={started:'попытка начата',connected:'соединение установлено',response:'ответ получен',rejected:'MAX отклонил запрос',failed:'ошибка',input_timeout:'истекло ожидание ввода',deferred:'очистка отложена',deleted:'удалено',authenticated:'вход подтверждён',resolved:'ссылка MAX проверена',confirmed:'членство подтверждено',auto_join_failed:'автовступление не удалось',membership_check_unavailable:'не удалось проверить членство',membership_not_confirmed:'MAX пока не подтвердил членство'};const result=row.duration_ms===undefined?(results[row.detail]||row.detail||''):(row.kind==='request_code'&&row.response_received?'MAX ответил на запрос кода; доставка SMS не подтверждена':(results[row.detail.split(':')[0]]||row.detail));const protocolStages=['handshake','request_code','otp','two_factor','login','profile'];const response=row.duration_ms!==undefined&&protocolStages.includes(row.kind)?(row.response_received?' · ответ получен':' · ответ не получен'):'';const timing=row.duration_ms!==undefined&&row.duration_ms!==null?` · ${row.duration_ms} мс`:'';const error=row.error_class?` · ${row.error_class}`:'';const ids=[row.attempt_id?`попытка ${row.attempt_id}`:'',row.account_id?`аккаунт ${row.account_id}`:'',row.ip_id?`IP ID ${row.ip_id}`:''].filter(Boolean).join(' · ');return `${ids?`${ids} · `:''}${result}${response}${timing}${error}`}
function authStateLabel(value){return ({authenticated:'авторизован',reauth_required:'нужен новый вход',unverified:'вход не подтверждён'})[value]||'вход не подтверждён'}
async function overview(generation=viewGeneration){const d=await api('/api/overview');if(generation!==viewGeneration||current!=='overview')return;$('#view').innerHTML=`<div class="grid">${[['Группы',d.counts.groups],['Сохранённые номера',d.counts.accounts],['Активные попытки',d.counts.onboarding_attempts],['Недельные слоты',d.counts.weekly_slots]].map(x=>`<div class="panel"><span class="muted">${x[0]}</span><div class="metric">${x[1]}</div></div>`).join('')}</div><div class="panel"><h3>Состояние</h3><p>Один номер отправляет не более одного сообщения в неделю. Неопределённые операции требуют ручной проверки.</p><p class="muted">${esc(d.run_wait_reason||'Вход MAX использует IPv4 VDS. Отправка идёт через закреплённый внешний SOCKS5.')}</p></div>`}
async function showOnboardingLink(groupId,action='read',generation=viewGeneration){
 const d=action==='read'
  ?await api(`/api/groups/${groupId}/onboarding-link`)
  :await api(`/api/groups/${groupId}/onboarding-link${action==='rotate'?'?rotate=1':''}`,{method:'POST',body:'{}'});
 if(generation!==viewGeneration||current!=='groups')return;const panel=$(`#invite-${groupId}`);if(!panel)return;
 const addNumber=$(`#add-number-${groupId}`);if(addNumber)addNumber.innerHTML=d.url?`<a class="button-link" href="${esc(d.url)}" target="_blank" rel="noopener noreferrer">Добавить номер</a>`:'<button disabled title="Создайте новую ссылку подключения ниже">Добавить номер</button>';
 if(d.url){panel.innerHTML=`<p class="muted">Ссылка действует до ${esc(formatDate(d.expires_at))}${d.max_uses?` · лимит ${d.max_uses} подключений`:''}</p><div class="invite-link"><a href="${esc(d.url)}" target="_blank" rel="noreferrer">${esc(d.url)}</a><button class="secondary" data-copy>Копировать</button></div><button class="secondary" data-rotate>Заменить ссылку</button><button class="quiet danger-text" data-revoke>Отозвать</button>`;panel.querySelector('[data-copy]').onclick=async e=>{const button=e.currentTarget;button.disabled=true;try{await navigator.clipboard.writeText(d.url);notice('Ссылка скопирована')}catch{notice('Не удалось скопировать ссылку',true)}finally{button.disabled=false}};panel.querySelector('[data-rotate]').onclick=async event=>{if(!confirm('Текущая ссылка перестанет работать, незавершённые подключения будут отменены. Заменить?'))return;const button=event.currentTarget;button.disabled=true;try{await showOnboardingLink(groupId,'rotate',generation)}catch(error){notice(error.message,true)}finally{button.disabled=false}};panel.querySelector('[data-revoke]').onclick=async()=>{if(!confirm('Отозвать ссылку? Незавершённые подключения будут отменены.'))return;const button=panel.querySelector('[data-revoke]');button.disabled=true;try{await api(`/api/groups/${groupId}/onboarding-link`,{method:'DELETE',body:'{}'});await showOnboardingLink(groupId,'read',generation)}catch(e){notice(e.message,true)}finally{button.disabled=false}}}
 else{const labels={missing:'Ссылка ещё не создана',expired:'Срок действия ссылки истёк',revoked:'Ссылка отозвана',exhausted:'Лимит подключений исчерпан'};const exhausted=d.status==='exhausted';panel.innerHTML=`<p class="muted">${labels[d.status]||'Ссылка недоступна'}</p><button class="secondary" data-create-link>${exhausted?'Заменить ссылку':'Создать новую ссылку'}</button>`;panel.querySelector('[data-create-link]').onclick=async e=>{if(exhausted&&!confirm('Лимит исчерпан. Выпустить новую ссылку?'))return;const button=e.currentTarget;button.disabled=true;try{await showOnboardingLink(groupId,exhausted?'rotate':'create',generation)}catch(error){notice(error.message,true)}finally{button.disabled=false}}}
}
async function groups(generation=viewGeneration){
 const [rows,settingsData]=await Promise.all([api('/api/groups'),api('/api/settings')]);appTimezone=settingsData.timezone||appTimezone;
 if(generation!==viewGeneration||current!=='groups')return;
 $('#view').innerHTML=`<details id="ip-panel" class="panel ip-panel"><summary>IP-адреса VDS для MAX <span id="ip-count" class="muted">Загрузка…</span></summary><div class="ip-panel-body"><p class="muted">62.109.10.109 исключён из соединений с MAX. Новые адреса после проверки нужно включить вручную.</p><button id="refresh-ips" class="secondary">Обновить IP</button><div id="ip-list"></div></div></details><div class="panel"><h3>Добавить группу</h3><form id="new-group" class="inline"><label>Название<input name="name" required></label><label>Ссылка MAX<input name="invite_link" placeholder="https://max.ru/join/…" required></label><button>Добавить</button><p class="error" data-form-error></p></form></div><div id="group-list"></div>`;
 $('#refresh-ips').onclick=async event=>{const button=event.currentTarget;button.disabled=true;try{await api('/api/ips/refresh',{method:'POST',body:'{}'});if(generation===viewGeneration){notice('Список IP обновлён');await ips(generation)}}catch(error){if(generation===viewGeneration)notice(error.message,true)}finally{button.disabled=false}};
 $('#new-group').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget,button=form.querySelector('button'),data=Object.fromEntries(new FormData(form));button.disabled=true;try{await api('/api/groups',{method:'POST',body:JSON.stringify(data)});if(generation===viewGeneration){notice('Группа добавлена');groups(generation)}}catch(error){if(generation===viewGeneration)form.querySelector('[data-form-error]').textContent=error.message}finally{button.disabled=false}};
  $('#group-list').innerHTML=rows.map(g=>`<div class="panel group-card"><div class="row group-heading"><div><strong>${esc(g.name)}</strong><div class="muted">Сохранено: ${g.account_count} · активных попыток: ${g.onboarding_attempt_count} · авторизовано: ${g.authenticated_account_count} · ${g.chat_id?'группа связана':'ожидает подключения'}</div></div><div class="actions"><span id="add-number-${g.id}"><button disabled>Добавить номер</button></span><button class="secondary" data-accounts="${g.id}">Номера</button><button class="secondary" data-verify="${g.id}" ${g.verifiable_account_count?'':'disabled title="Нужен авторизованный номер с доступным IP"'}>Проверить назначение</button><button class="secondary" data-active="${g.id}" data-enabled="${g.active?1:0}">${g.active?'Остановить':'Запустить'}</button></div></div><section class="group-link"><h4>Ссылка подключения</h4><div id="invite-${g.id}"><span class="muted">Загружаем ссылку…</span></div></section><form class="inline edit-group" data-group="${g.id}"><label>Название<input name="name" value="${esc(g.name)}" required></label><label>Ссылка MAX<input name="invite_link" value="${esc(g.invite_link||'')}" required></label><button>Сохранить изменения</button><p class="error" data-form-error></p></form>${chatPolicyPanel(g)}<div id="accounts-${g.id}"></div></div>`).join('')||'<div class="panel">Пока нет групп</div>';
 for(const form of document.querySelectorAll('.chat-policy-form'))form.onsubmit=event=>saveChatPolicy(event,generation);
 await ips(generation);
 for(const g of rows)showOnboardingLink(g.id,'read',generation).catch(error=>{if(generation===viewGeneration)$(`#invite-${g.id}`).textContent=error.message});
 document.querySelectorAll('[data-accounts]').forEach(button=>button.onclick=()=>accounts(button.dataset.accounts,generation));
 document.querySelectorAll('[data-verify]').forEach(button=>button.onclick=async()=>{button.disabled=true;try{const result=await api(`/api/groups/${button.dataset.verify}/verify-destination`,{method:'POST',body:'{}'});if(generation===viewGeneration){notice(`Назначение проверено: ${result.verified_accounts} подтверждено, ${result.accounts_needing_membership} требуют вступления`);groups(generation)}}catch(error){if(generation===viewGeneration)notice(error.message,true)}finally{button.disabled=false}});
 document.querySelectorAll('[data-active]').forEach(button=>button.onclick=async()=>{const enabled=button.dataset.enabled!=='1';button.disabled=true;try{await api(`/api/groups/${button.dataset.active}/active`,{method:'POST',body:JSON.stringify({enabled})});if(generation===viewGeneration)groups(generation)}catch(error){if(generation===viewGeneration)notice(error.message,true)}finally{button.disabled=false}});
 document.querySelectorAll('.edit-group').forEach(form=>form.onsubmit=async event=>{event.preventDefault();const button=form.querySelector('button');button.disabled=true;try{await api(`/api/groups/${form.dataset.group}`,{method:'PUT',body:JSON.stringify(Object.fromEntries(new FormData(form)))});if(generation===viewGeneration){notice('Настройки группы сохранены');groups(generation)}}catch(error){if(generation===viewGeneration)form.querySelector('[data-form-error]').textContent=error.message}finally{button.disabled=false}});
}
function chatPolicyPanel(group){
 if(!group.chat_id)return '';
 return `<details class="chat-policy group-link"><summary>Правила отправки в чат MAX</summary>
  <p class="muted">Действуют для всех групп панели, которые отправляют в этот чат. Лимит 0 отключает дневное ограничение.</p>
  <form class="chat-policy-form" data-group="${group.id}" data-chat-id="${esc(group.chat_id)}">
   <div class="split">
    <label>Пауза между отправками, сек<input name="pause_seconds" type="number" min="0" max="86400" value="${group.chat_pause_seconds}" required></label>
    <label>Лимит сообщений в день<input name="daily_limit" type="number" min="0" max="2147483647" value="${group.chat_daily_limit}" required></label>
   </div>
   <button>Сохранить правила чата</button><p class="error" role="alert"></p>
  </form></details>`;
}
async function saveChatPolicy(event,generation){
 event.preventDefault();
 const form=event.currentTarget,button=form.querySelector('button'),error=form.querySelector('.error');
 const {pause_seconds,daily_limit}=form.elements;
 button.disabled=true;error.textContent='';
 try{
  const saved=await api(`/api/groups/${form.dataset.group}/chat-dispatch-policy`,{method:'PUT',body:JSON.stringify({
   chat_id:form.dataset.chatId,pause_seconds:pause_seconds.valueAsNumber,daily_limit:daily_limit.valueAsNumber,
  })});
  if(generation!==viewGeneration)return;
  for(const other of document.querySelectorAll('.chat-policy-form')){
   if(other.dataset.chatId!==saved.chat_id)continue;
   other.elements.pause_seconds.value=saved.pause_seconds;
   other.elements.daily_limit.value=saved.daily_limit;
  }
  notice('Правила чата сохранены');
 }catch(err){if(form.isConnected)error.textContent=err.message}finally{button.disabled=false}
}
async function ips(generation=viewGeneration){
 try{
  const rows=await api('/api/ips');if(generation!==viewGeneration||current!=='groups')return;
  const panel=$('#ip-list');if(!panel)return;
  if(!$('#send-proxy-pool'))panel.insertAdjacentHTML('afterend','<section id="send-proxy-pool" class="group-link" hidden></section>');
  $('#ip-count').textContent=`Всего: ${rows.length} · включено: ${rows.filter(ip=>ip.enabled).length}`;
  panel.innerHTML=rows.map(ip=>`<div class="row"><span><strong>${esc(ip.address)}</strong><small>${ip.available?'Доступен на VDS':'Недоступен на VDS'} · ${ip.enabled?'включён':'выключен'} · назначено ${ip.assigned_count} · авторизовано ${ip.authenticated_count} · попыток ${ip.in_progress_count} · не подтверждено ${ip.unconfirmed_count}</small></span><div class="actions"><button class="secondary" data-ip-toggle="${ip.id}" data-enabled="${ip.enabled?1:0}" ${!ip.available&&!ip.enabled?'disabled':''}>${ip.enabled?'Отключить':'Включить'}</button><button class="secondary" data-ip-proxies="${ip.id}">Прокси</button></div></div>`).join('')||'<p class="muted">Доступных IP пока нет. Нажмите «Обновить IP».</p>';
  panel.querySelectorAll('[data-ip-toggle]').forEach(button=>button.onclick=async()=>{const enabled=button.dataset.enabled!=='1',ip=rows.find(item=>Number(item.id)===Number(button.dataset.ipToggle));if(!enabled&&ip?.assigned_count&&!confirm(`Отключить ${ip.address}? Назначенные аккаунты будут приостановлены.`))return;button.disabled=true;try{await api(`/api/ips/${button.dataset.ipToggle}`,{method:'PATCH',body:JSON.stringify({enabled})});if(generation===viewGeneration){notice(enabled?'IP включён':'IP отключён');await ips(generation)}}catch(error){if(generation===viewGeneration)notice(error.message,true)}finally{button.disabled=false}});
  for(const button of panel.querySelectorAll('[data-ip-proxies]')){
   const ip=rows.find(row=>String(row.id)===button.dataset.ipProxies);
   button.onclick=()=>showProxyPool(ip,generation);
  }
 }catch(error){if(generation===viewGeneration){const panel=$('#ip-list');if(panel)panel.innerHTML=`<p class="error" role="alert">${esc(error.message)}</p>`;const count=$('#ip-count');if(count)count.textContent='Не удалось загрузить IP'}}
}
function proxyCheckLabel(status){
 return ({
  unchecked:'Проверка ещё не запускалась',
  ok:'TLS до MAX установлен',
  connection_failed:'Не удалось подключиться к SOCKS5',
  socks_timeout:'Истекло время подключения через SOCKS5',
  auth_failed:'SOCKS5 отклонил авторизацию',
  tunnel_failed:'Не удалось открыть туннель SOCKS5 до MAX',
  tls_failed:'Не удалось установить TLS до MAX',
  source_ip_mismatch:'Исходящий IPv4 VDS не подтверждён',
  config_invalid:'Данные прокси не удалось прочитать',
  check_unavailable:'Проверка недоступна',
 })[status]||'Проверка недоступна';
}
async function showProxyPool(ip,generation,imported=[],focusSelector='h4'){
 const panel=$('#send-proxy-pool');
 if(!panel||generation!==viewGeneration)return;
 const endpoint=`/api/ips/${ip.id}/send-proxies`;
 const request=Symbol();
 panel.poolRequest=request;
 const currentPool=()=>panel.isConnected&&panel.poolRequest===request&&generation===viewGeneration;
 panel.hidden=false;
 panel.textContent='Загружаем прокси…';
 try{
  const rows=await api(endpoint);
  if(!currentPool())return;
  const batch=imported.length?[...new Set(imported)]:rows.filter(proxy=>proxy.check_status==='unchecked').slice(0,30).map(proxy=>proxy.id);
  panel.innerHTML=`<h4 tabindex="-1">Прокси для ${esc(ip.address)}</h4><form class="proxy-import">
   <label>Адрес SOCKS5<input type="password" name="url" placeholder="socks5://…" autocomplete="new-password" maxlength="2048"></label>
   <label>Список SOCKS5 в TXT<input type="file" name="list" accept=".txt,text/plain"></label>
   <button>Добавить прокси</button><p class="error" role="alert"></p></form>
   ${imported.length?`<p class="muted">Номера в порядке импорта: ${imported.map(id=>`№${id}`).join(', ')}</p>`:''}
   ${batch.length?`<button type="button" class="secondary" data-check-batch>${imported.length?'Проверить импортированные':'Проверить непроверенные'} (${batch.length})</button>`:''}
   <p class="muted" data-proxy-progress role="status" hidden></p>
   <div class="proxy-entries">${rows.map(proxy=>{
    const checked=proxy.check_status==='ok';
    const state=proxy.enabled?(checked?'Включён':'Приостановлен'):'Выключен';
    return `<div class="row"><span>Прокси №${proxy.id} · ${state}<small>Назначено аккаунтам: ${proxy.assigned_count}</small>
     <small>${esc(proxyCheckLabel(proxy.check_status))}${proxy.last_checked_at?` · ${esc(formatDate(proxy.last_checked_at))}`:''}</small></span>
     <div class="actions"><button class="secondary" data-check-proxy="${proxy.id}">Проверить</button>
     <button class="secondary" data-toggle-proxy="${proxy.id}" data-enabled="${proxy.enabled}" ${proxy.enabled||checked?'':'disabled'}>${proxy.enabled?'Отключить':'Включить'}</button></div></div>`;
   }).join('')||'<p class="muted">Прокси для этого IP пока не добавлены.</p>'}</div>`;
  (panel.querySelector(focusSelector)||panel.querySelector('h4')).focus();
  const form=panel.querySelector('form');
  form.onsubmit=async event=>{
   event.preventDefault();
   const button=form.querySelector('button'),error=form.querySelector('.error');
   const file=form.elements.list.files[0];
   button.disabled=true;error.textContent='';
   try{
    if(file&&file.size>65536)throw new Error('Загрузите TXT до 64 КБ.');
    const sources=[form.elements.url.value,file?await file.text():''];
    const urls=sources.join('\n').split(/\r?\n/).map(line=>line.trim()).filter(Boolean);
    if(urls.length<1||urls.length>30)throw new Error('Укажите от 1 до 30 адресов SOCKS5, по одному на строку.');
    const result=await api(endpoint,{method:'POST',body:JSON.stringify({urls})});
    form.reset();
    if(currentPool()){notice(`Добавлено: ${result.added} · уже в пуле: ${result.duplicates}`);await showProxyPool(ip,generation,result.proxy_ids)}
   }catch(err){if(currentPool())error.textContent=err.message}finally{button.disabled=false}
  };
  async function checkProxies(ids,selector){
   const progress=panel.querySelector('[data-proxy-progress]');
   const controls=[...panel.querySelectorAll('[data-check-batch],[data-check-proxy],[data-toggle-proxy]')].filter(button=>!button.disabled);
   controls.forEach(button=>button.disabled=true);
   progress.hidden=false;
   progress.textContent='Проверяем соединение через SOCKS5…';
   try{
    const results=await api(`${endpoint}/check`,{method:'POST',body:JSON.stringify({proxy_ids:ids})});
    if(currentPool()){
     notice(`Доступно через SOCKS5: ${results.filter(row=>row.check_status==='ok').length} из ${results.length}`);
     await showProxyPool(ip,generation,imported,selector);
    }
   }catch(error){if(currentPool())notice(error.message,true)}finally{
    controls.forEach(button=>button.disabled=false);
    progress.hidden=true;
   }
  }
  const batchButton=panel.querySelector('[data-check-batch]');
  if(batchButton)batchButton.onclick=()=>checkProxies(batch,'[data-check-batch]');
  for(const button of panel.querySelectorAll('[data-check-proxy]')){
   const id=Number(button.dataset.checkProxy);
   button.onclick=()=>checkProxies([id],`[data-check-proxy="${id}"]`);
  }
  for(const button of panel.querySelectorAll('[data-toggle-proxy]'))button.onclick=async()=>{
   button.disabled=true;
   try{
    await api(`${endpoint}/${button.dataset.toggleProxy}`,{method:'PATCH',body:JSON.stringify({enabled:button.dataset.enabled==='0'})});
    if(currentPool())await showProxyPool(ip,generation,imported,`[data-toggle-proxy="${button.dataset.toggleProxy}"]`);
   }catch(err){if(currentPool())notice(err.message,true)}finally{button.disabled=false}
  };
 }catch(error){if(currentPool())panel.textContent=error.message}
}
async function accounts(id,generation=viewGeneration){
 try{
  const [rows,ipRows]=await Promise.all([api(`/api/groups/${id}/accounts`),api('/api/ips')]);if(generation!==viewGeneration||current!=='groups')return;
  const panel=$(`#accounts-${id}`);if(!panel)return;
  panel.innerHTML=`<div class="panel"><h4>Сохранённые номера и попытки</h4>${rows.map(account=>{const options=ipRows.filter(ip=>ip.enabled&&ip.available).map(ip=>`<option value="${ip.id}" ${Number(ip.id)===Number(account.ip_id)?'selected':''}>${esc(ip.address)}</option>`).join('');const currentIp=account.ip_id&&(!account.ip_enabled||!account.ip_available)?`<option value="${account.ip_id}" selected disabled>${esc(account.ip_address)} (недоступен)</option>`:'';const noIp=!account.ip_id?'<option value="" selected disabled>IP не назначен</option>':'';const stage=account.onboarding_state?` · подключение: ${esc(accountStatus(account.onboarding_state))}`:'';const issue=account.onboarding_error?`<small class="error">${esc(humanError(account.onboarding_error))}</small>`:'';const lifecycle=account.lifecycle==='delete_pending'?'<small class="error">Удаление не завершено. Повторите его после сверки отправок.</small>':'';return `<div class="row"><div><strong>${esc(account.full_name)}</strong><div class="muted">ID ${esc(account.id)} · ${account.lifecycle==='delete_pending'?'удаление не завершено':esc(accountStatus(account.status))} · ${esc(authStateLabel(account.auth_state))} · ${account.send_weekday===null?'день не назначен':['Пн','Вт','Ср','Чт','Пт','Сб','Вс'][account.send_weekday]} · слот: ${esc(accountStatus(account.slot_status)||'нет')}${stage}</div><small>IP входа: ${esc(account.ip_address||'не назначен')} · Прокси отправки: ${account.send_proxy_id?`№${account.send_proxy_id}${account.send_proxy_enabled?(account.send_proxy_check_status==='ok'?'':' (приостановлен)'):' (выключен)'}`:'не назначен'} · ${esc(formatDay(account.scheduled_date))} · ${esc(humanError(account.error_code||''))}</small>${issue}${lifecycle}</div><div class="actions"><select data-account-ip="${account.id}" aria-label="IP MAX для ${esc(account.full_name)}" ${account.lifecycle!=='active'||ipRows.every(ip=>!ip.enabled||!ip.available)?'disabled':''}>${currentIp}${noIp}${options}</select>${account.auth_state==='authenticated'&&account.ip_id&&account.lifecycle==='active'?`<button class="secondary" data-account-proxy="${account.id}">Прокси отправки</button><form class="account-proxy-form" hidden></form>`:''}<button class="quiet danger-text" data-account-delete="${account.id}">${account.lifecycle==='delete_pending'?'Повторить удаление':'Удалить номер и сессию'}</button></div></div>`}).join('')||'<p class="muted">Номеров и попыток нет.</p>'}</div>`;
  panel.querySelectorAll('[data-account-ip]').forEach(select=>select.onchange=async()=>{select.disabled=true;try{await api(`/api/accounts/${select.dataset.accountIp}/ip`,{method:'POST',body:JSON.stringify({ip_id:Number(select.value)})});if(generation===viewGeneration){notice('IP переназначен');accounts(id,generation)}}catch(error){if(generation===viewGeneration)notice(error.message,true)}finally{select.disabled=false}});
  for(const button of panel.querySelectorAll('[data-account-proxy]')){
   const account=rows.find(row=>String(row.id)===button.dataset.accountProxy);
   button.onclick=()=>proxyAssignmentForm(button,account,id,generation);
  }
  panel.querySelectorAll('[data-account-delete]').forEach(button=>button.onclick=async()=>{if(!confirm('Удалить номер и все поколения его сессии? История отправок останется, а номер можно будет подключить заново. Если есть неопределённая отправка, сначала сверьте её в журнале.'))return;button.disabled=true;try{await api(`/api/accounts/${button.dataset.accountDelete}`,{method:'DELETE',body:'{}'});if(generation===viewGeneration){notice('Номер и сессии удалены');await accounts(id,generation)}}catch(error){if(generation===viewGeneration)notice(error.message,true)}finally{button.disabled=false}});
 }catch(error){if(generation===viewGeneration)notice(error.message,true)}
}
async function proxyAssignmentForm(button,account,groupId,generation){
 const form=button.nextElementSibling;
 button.disabled=true;
 try{
  const pool=await api(`/api/ips/${account.ip_id}/send-proxies`);
  if(!form.isConnected||generation!==viewGeneration)return;
  const choices=pool.filter(proxy=>proxy.enabled&&proxy.check_status==='ok');
  form.hidden=false;
  if(!choices.length){form.textContent='Включите прокси для IPv4 этого аккаунта.';return}
  form.innerHTML=`<label>Прокси для отправки<select name="proxy_id">${choices.map(proxy=>`<option value="${proxy.id}" ${proxy.id===account.send_proxy_id?'selected':''}>Прокси №${proxy.id}</option>`).join('')}</select></label><button>Назначить</button><p class="error" role="alert"></p>`;
  form.elements.proxy_id.focus();
  form.onsubmit=async event=>{
   event.preventDefault();
   const submit=form.querySelector('button');submit.disabled=true;
   try{
    await api(`/api/accounts/${account.id}/send-proxy`,{method:'PUT',body:JSON.stringify({proxy_id:Number(form.elements.proxy_id.value)})});
    if(generation===viewGeneration){notice('Прокси назначен');await accounts(groupId,generation)}
   }catch(error){if(form.isConnected)form.querySelector('.error').textContent=error.message}
   finally{submit.disabled=false}
  };
 }catch(error){if(form.isConnected)notice(error.message,true)}finally{button.disabled=false}
}
async function messages(generation=viewGeneration){
 const data=await api('/api/messages');
 if(generation!==viewGeneration||current!=='messages')return;
 $('#view').innerHTML=`<div class="panel"><h3>Общий пул</h3><p class="muted">По одному тексту на строку. Тексты повторяются только после исчерпания перемешанного цикла.</p><textarea id="texts" placeholder="Текст сообщения">${esc(data.texts.join('\n'))}</textarea><div class="row"><span class="muted">Версия ${data.version||'—'} · ${data.texts.length} текстов</span><button id="save-texts">Сохранить новый цикл</button></div><label class="field">Импорт TXT<input type="file" id="txt-file" accept=".txt,text/plain"></label><p id="messages-error" class="error" role="alert"></p></div>`;
 $('#txt-file').onchange=async event=>{
  const input=event.currentTarget,file=input.files[0];
  if(!file)return;
  try{const text=await file.text();if(generation===viewGeneration&&current==='messages')$('#texts').value=text}
  catch{if(generation===viewGeneration)$('#messages-error').textContent='Не удалось прочитать TXT-файл.'}
 };
 $('#save-texts').onclick=async event=>{
  const button=event.currentTarget;button.disabled=true;
  try{
   const list=$('#texts').value.split(/\r?\n/).map(line=>line.trim()).filter(Boolean);
   const result=await api('/api/messages',{method:'PUT',body:JSON.stringify({texts:list})});
   if(generation===viewGeneration){notice(`Сохранена версия ${result.version}`);await messages(generation)}
  }catch(error){if(generation===viewGeneration)$('#messages-error').textContent=error.message}
  finally{button.disabled=false}
 };
}
async function settings(generation=viewGeneration){
 const data=await api('/api/settings');
 if(generation!==viewGeneration||current!=='settings')return;
 $('#view').innerHTML=`<div class="panel"><form id="settings-form"><label>Часовой пояс<input name="timezone" value="${esc(data.timezone)}" required></label><div class="split"><label>Окна будней<input name="send_windows_weekday" value="${esc(data.send_windows_weekday)}"></label><label>Окна выходных<input name="send_windows_weekend" value="${esc(data.send_windows_weekend)}"></label></div><p class="muted">Формат: 09:00-13:00,16:00-21:00</p><div class="split"><label>Пауза от, сек<input type="number" min="5" name="delay_min_sec" value="${data.delay_min_sec}"></label><label>Пауза до, сек<input type="number" min="5" name="delay_max_sec" value="${data.delay_max_sec}"></label></div><label><input type="checkbox" name="auto_run" ${data.auto_run?'checked':''} style="display:inline;width:auto"> Автозапуск после рестарта</label><button>Сохранить</button><p id="settings-error" class="error" role="alert"></p></form><p class="muted">Часовой пояс и окна применяются к ближайшей отправке. Дата и текст фиксируются при подготовке слота. Пропущенные дни не переносятся.</p></div>`;
 $('#settings-form').onsubmit=async event=>{
  event.preventDefault();const form=event.currentTarget,button=form.querySelector('button');button.disabled=true;
  const values=Object.fromEntries(new FormData(form));values.auto_run=form.elements.auto_run.checked;
  for(const key of ['delay_min_sec','delay_max_sec'])values[key]=Number(values[key]);
  try{await api('/api/settings',{method:'PUT',body:JSON.stringify(values)});if(generation===viewGeneration){appTimezone=values.timezone;notice('Настройки сохранены')}}
  catch(error){if(generation===viewGeneration)$('#settings-error').textContent=error.message}
  finally{button.disabled=false}
 };
}
async function logs(generation=viewGeneration){
 const rows=await api('/api/log');
 if(generation!==viewGeneration||current!=='log')return;
 $('#view').innerHTML=`<div class="panel"><table class="table"><thead><tr><th>Время</th><th>Событие</th><th>Группа</th><th>Детали / действие</th></tr></thead><tbody>${rows.map(row=>`<tr><td>${esc(formatDate(row.created_at))}</td><td>${esc(accountStatus(row.kind))}</td><td>${esc(row.group_id||'—')}</td><td>${esc(eventDetail(row))} ${row.kind==='unknown'?`<div class="actions"><button class="secondary" data-resolve-accepted="${esc(row.operation_id)}">Подтвердить отправку</button><button class="secondary" data-resolve-unsent="${esc(row.operation_id)}">Подтвердить, что не отправлено</button></div>`:''}</td></tr>`).join('')}</tbody></table></div>`;
 document.querySelectorAll('[data-resolve-accepted]').forEach(button=>button.onclick=async()=>{
  const messageId=prompt('Введите ID сообщения MAX после ручной проверки:');if(!messageId)return;
  button.disabled=true;
  try{await api(`/api/operations/${button.dataset.resolveAccepted}/resolve`,{method:'POST',body:JSON.stringify({outcome:'accepted',provider_message_id:messageId})});if(generation===viewGeneration){notice('Слот учтён как отправленный');await logs(generation)}}
  catch(error){if(generation===viewGeneration)notice(error.message,true)}
  finally{button.disabled=false}
 });
 document.querySelectorAll('[data-resolve-unsent]').forEach(button=>button.onclick=async()=>{
  if(!confirm('Вы проверили MAX и подтвердили, что сообщения нет? Слот может быть отправлен повторно в доступное окно.'))return;
  button.disabled=true;
  try{await api(`/api/operations/${button.dataset.resolveUnsent}/resolve`,{method:'POST',body:JSON.stringify({outcome:'confirmed_not_sent'})});if(generation===viewGeneration){notice('Результат сохранён');await logs(generation)}}
  catch(error){if(generation===viewGeneration)notice(error.message,true)}
  finally{button.disabled=false}
 });
}
api('/api/auth/me').then(showApp).catch(showLogin);
