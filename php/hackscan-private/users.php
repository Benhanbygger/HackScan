<?php
declare(strict_types=1);
function hs_users_schema(PDO $db): void {
    $db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL COLLATE NOCASE UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user','viewer')), active INTEGER NOT NULL DEFAULT 1, session_version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)");
    $db->exec('CREATE TABLE IF NOT EXISTS user_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor INTEGER NOT NULL, subject INTEGER NOT NULL, event TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
    $legacy=hs_get($db,'password_hash');
    if ($legacy!=='' && (int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn()===0) $db->prepare("INSERT OR IGNORE INTO users(username,password_hash,role) VALUES('admin',?,'admin')")->execute([$legacy]);
}
function hs_username(mixed $name): string {
    if (!is_string($name) || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,49}$/D',$name)) throw new InvalidArgumentException('Brugernavn skal være 3–50 tegn: bogstaver, tal, punktum, bindestreg eller underscore.');
    return strtolower($name);
}
function hs_password(mixed $password): string {
    if (!is_string($password) || strlen($password)<14 || strlen($password)>72) throw new InvalidArgumentException('Vælg en adgangskode på 14–72 bytes.');
    return password_hash($password,PASSWORD_DEFAULT);
}
function hs_user_by_name(PDO $db,string $name): ?array {
    $q=$db->prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE'); $q->execute([$name]); return $q->fetch()?:null;
}
function hs_current_user(PDO $db,array $session): ?array {
    if (empty($session['user_id']) || empty($session['auth']) || (int)$session['auth']<time()-43200) return null;
    $q=$db->prepare('SELECT id,username,role,active,session_version FROM users WHERE id=?'); $q->execute([(int)$session['user_id']]); $u=$q->fetch();
    if (!$u || !$u['active'] || (int)$u['session_version']!==(int)($session['session_version']??0)) return null;
    return $u;
}
function hs_user_audit(PDO $db,int $actor,int $subject,string $event): void {
    $db->prepare('INSERT INTO user_audit(actor,subject,event) VALUES(?,?,?)')->execute([$actor,$subject,$event]);
    $db->exec('DELETE FROM user_audit WHERE id NOT IN (SELECT id FROM user_audit ORDER BY id DESC LIMIT 1000)');
}
function hs_user_create(PDO $db,array $actor,mixed $username,mixed $password,mixed $role): int {
    if ($actor['role']!=='admin') throw new RuntimeException('Kun administratorer kan oprette brugere.');
    $name=hs_username($username); $hash=hs_password($password);
    if (!in_array($role,['admin','user','viewer'],true)) throw new InvalidArgumentException('Ugyldig rolle.');
    if (hs_user_by_name($db,$name)) throw new InvalidArgumentException('Brugernavnet findes allerede.');
    $db->prepare('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)')->execute([$name,$hash,$role]);
    $id=(int)$db->lastInsertId(); hs_user_audit($db,(int)$actor['id'],$id,'Oprettet: '.$role); return $id;
}
function hs_user_update(PDO $db,array $actor,int $id,mixed $role,bool $active,?string $password=null): void {
    if ($actor['role']!=='admin') throw new RuntimeException('Kun administratorer kan ændre brugere.');
    if (!in_array($role,['admin','user','viewer'],true)) throw new InvalidArgumentException('Ugyldig rolle.');
    if ($id===(int)$actor['id'] && (!$active || $role!=='admin')) throw new InvalidArgumentException('Du kan ikke deaktivere eller nedgradere din egen administratorkonto.');
    $hash=$password!==null && $password!==''?hs_password($password):null;
    $db->exec('BEGIN IMMEDIATE');
    try {
        $q=$db->prepare('SELECT * FROM users WHERE id=?'); $q->execute([$id]); $old=$q->fetch();
        if (!$old) throw new InvalidArgumentException('Brugeren findes ikke.');
        if ($old['role']==='admin' && $old['active'] && (!$active || $role!=='admin') && (int)$db->query("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1")->fetchColumn()<=1) throw new InvalidArgumentException('Den sidste aktive administrator kan ikke fjernes.');
        $q=$db->prepare('UPDATE users SET role=?,active=?,password_hash=?,session_version=session_version+1 WHERE id=?');
        $q->execute([$role,$active?1:0,$hash??$old['password_hash'],$id]);
        hs_user_audit($db,(int)$actor['id'],$id,'Ændret: '.$role.($active?' · aktiv':' · deaktiveret').($hash?' · adgangskode nulstillet':''));
        $db->exec('COMMIT');
    } catch (Throwable $e) { $db->exec('ROLLBACK'); throw $e; }
}
function hs_admin_page(array $user,string $csrf): never {
    hs_page('<div id="administration" class="report-page" data-csrf="'.h($csrf).'" data-self="'.(int)$user['id'].'"><div class="report-nav"><a href="index.php">← Dashboard</a><span class="muted">Administrator: '.h($user['username']).'</span></div><header class="report-heading"><div><p class="eyebrow">ADMINISTRATION</p><h1>Brugere og adgang</h1></div></header><p class="report-disclaimer">Administratorer administrerer brugere og scanner. Brugere scanner og læser rapporter. Læsere kan kun se rapporter og eksportere data. Brug personlige adgangskoder og del dem sikkert — aldrig i URL’er.</p><section class="report-method"><h2>Opret bruger</h2><form id="create-user" class="user-form"><label>Brugernavn<input id="new-username" autocomplete="off" minlength="3" maxlength="50" required></label><label>Rolle<select id="new-role"><option value="user">Bruger — scan og læs</option><option value="viewer">Læser — kun læsning</option><option value="admin">Administrator</option></select></label><label>Adgangskode<input id="new-password" type="password" autocomplete="new-password" minlength="14" maxlength="72" required></label><button class="button">Opret bruger</button></form></section><p id="admin-message" class="muted" role="status"></p><section class="report-method"><h2>Eksisterende brugere</h2><div id="user-list" class="user-list"></div></section><section class="report-method"><h2>Ryd alle resultater</h2><p>Stopper en eventuel scanning og sletter alle domæners scanningsresultater, sikkerhedsrapporter og historik for alle brugere. Brugere, adgangskoder, indstillinger og den gemte domæneliste bevares. Sletningen kan ikke fortrydes. Hent eventuelt CSV fra dashboardet først.</p><button id="clear-results" class="button secondary">Ryd alle resultater</button></section><section class="report-method"><h2>Seneste administrationsændringer</h2><div id="audit-list"></div></section></div><script src="admin.js?v=0.4.2" defer></script>','Administration · HackScan');
}
