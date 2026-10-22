<?php
declare(strict_types=1);
function hs_details_page(PDO $db,string $domain,string $csrf,bool $canScan=true): never {
    $q=$db->prepare('SELECT * FROM results WHERE domain=?'); $q->execute([$domain]); $result=$q->fetch();
    if (!$result) { http_response_code(404); hs_page('<section class="login"><h1>Domænet blev ikke fundet</h1><a href="index.php">Til dashboard</a></section>'); }
    $r=hs_report_get($db,$domain);
    $intro='<div class="report-page" id="report" data-domain="'.h($domain).'" data-csrf="'.h($csrf).'"><div class="report-nav"><a href="index.php">← Dashboard</a><a class="button secondary" href="'.h('https://'.$domain.'/').'" target="_blank" rel="noopener noreferrer">Åbn hjemmeside ↗</a></div><header class="report-heading"><div><p class="eyebrow">DOMÆNERAPPORT · OFFENTLIGE SIKKERHEDSSIGNALER</p><h1>'.h($domain).'</h1><p class="muted">Seneste redirect-kontrol: '.h($result['checked_at']).' UTC · '.h($result['status']).'</p></div><button class="button" id="reassess"'.($canScan?'':' disabled').'>Kontrollér domænet igen</button></header><p id="detail-message" class="muted" role="status"></p>';
    if (!$r) hs_page($intro.'<section class="report-empty"><h2>Endnu ingen sikkerhedsvurdering</h2><p>Dette resultat stammer fra en tidligere redirect-kontrol. Siden har ingen sikkerhedskarakter, før den er blevet scannet med de nye kontroller.</p><p>Brug “Kontrollér domænet igen”, og lad dashboardet stå åbent, mens kontrollerne gennemføres.</p></section></div><script src="detail.js?v=0.4.0" defer></script>');
    $rating=$r['rating'];
    if ($result['status']==='pending') $intro.='<p class="report-disclaimer">En ny kontrol afventer. Her vises den seneste gemte sikkerhedsvurdering, ikke resultatet af den nye kontrol.</p>';
    $intro.='<p class="muted">HTTP-fund gælder det hentede slutmål: '.h($r['url']).'. DNS-fund gælder '.h($domain).'.</p>';
    $classes=['vulnerability'=>'Sårbarhed','indicator'=>'Kompromitteringsindikator','risk'=>'Risikofaktor'];
    $severities=['critical'=>'Kritisk','high'=>'Høj','medium'=>'Mellem','low'=>'Lav'];
    $states=['finding'=>'Fund — bør valideres','pass'=>'Kontrolleret (afgrænset)','observed'=>'Observation','unknown'=>'Ukendt','not_tested'=>'Ikke udført','not_applicable'=>'Ikke relevant'];
    $confidences=['high'=>'Høj','medium'=>'Mellem','low'=>'Lav','none'=>'Ikke fastlagt'];
    $intro.='<section class="rating-panel"><div class="grade grade-'.h(strtolower($rating['grade']??'unknown')).'"><strong>'.h($rating['grade']??'—').'</strong><span>'.($rating['score']!==null?(int)$rating['score'].' / 100':'Ikke vurderbar').'</span></div><div><p class="eyebrow">FORELØBIG SIKKERHEDSKARAKTER</p><h2>En vurdering af de observerede signaler</h2><p>'.(int)$rating['checked'].' af '.(int)$rating['total'].' kontroller har afgrænsede observationer. Resten er ukendte eller ikke udført og tæller <strong>ikke som beståede</strong>.</p><p class="muted">'.h($r['assessed_at']).' UTC · '.($r['complete']?'De planlagte offentlige trin er afsluttet.':'Vurderingen er ikke afsluttet; nogle trin kan stadig afvente.').'</p></div></section>';
    $intro.='<div class="risk-summary">';
    foreach ($classes as $key=>$title) $intro.='<section><span class="class-label '.h($key).'">'.h($title).'</span><strong>'.(int)$rating['classes'][$key].'</strong><p>Fund, som kræver nærmere vurdering</p></section>';
    $intro.='</div><p class="report-disclaimer">Karakteren er ikke et bevis på, at siden er sikker eller hacket. Versionsheaders kan være misvisende; CVE-spor er mulige versionsmatch, ikke påvist udnyttelighed. En normal viderestilling giver ikke i sig selv risikopoint.</p>';
    $unknown=count(array_filter($r['controls'],fn($c)=>in_array($c['state'],['unknown','not_tested'],true)));
    $intro.='<div class="check-filters" role="group" aria-label="Filtrer sikkerhedskontroller"><button data-check-filter="finding" class="selected">Fund ('.(int)$rating['findings'].')</button><button data-check-filter="all">Alle kontroller ('.count($r['controls']).')</button><button data-check-filter="unknown">Ukendt / ikke udført ('.$unknown.')</button></div><p id="no-checks" class="muted" hidden>Ingen kontroller i denne visning. Det betyder ikke, at alle øvrige kontroller er bestået.</p><div class="check-list">';
    foreach ($r['controls'] as $c) {
        $intro.='<article class="check-card" data-check-state="'.h($c['state']).'"><div class="check-top"><span class="class-label '.h($c['class']).'">'.h($classes[$c['class']]).'</span><span class="check-state '.h($c['state']).'">'.h($states[$c['state']]).'</span></div><h2>'.h($c['title']).'</h2><p class="check-meta">Potentiel alvor: <strong>'.h($severities[$c['severity']]).'</strong> · Sikkerhed i observationen: '.h($confidences[$c['confidence']]).'</p><p>'.h($c['evidence']).'</p>';
        if ($c['recommendation']!=='') $intro.='<div class="recommendation"><strong>Forslag til forbedring</strong><p>'.h($c['recommendation']).'</p></div>';
        if ($c['source']!=='' && str_starts_with($c['source'],'https://')) $intro.='<a class="source-link" href="'.h($c['source']).'" target="_blank" rel="noopener noreferrer">Officiel kilde / advisory ↗</a>';
        $intro.='</article>';
    }
    $intro.='</div><section class="report-method"><h2>Metode og afgrænsning</h2><p>'.h($rating['method']).'</p><ul>';
    foreach ($r['limitations'] as $limitation) $intro.='<li>'.h($limitation).'</li>';
    $intro.='</ul><p>Kun begrænsede metadata og fingeraftryk gemmes. HTML, cookieværdier og formularværdier gemmes ikke. Historik: højst 10 sikkerhedsoversigter pr. domæne.</p>';
    foreach ($r['intel']??[] as $kind=>$meta) $intro.='<p>'.h($kind==='kev'?'CISA KEV':'Officielle WordPress-data').': '.h($meta['updated_at']??'Ikke tilgængelig').($meta['error']!==''?' · '.h($meta['error']):'').'</p>';
    $intro.='</section><section class="report-method"><h2>HTTP-forløb</h2><p>WWW og HTTPS-normalisering tælles ikke som eksterne redirects.</p>';
    $q=$db->prepare('SELECT * FROM redirect_hops WHERE domain=? ORDER BY seq'); $q->execute([$domain]);
    foreach ($q as $hop) $intro.='<p><span class="'.($hop['external']?'http-code-badge':'soft-label').'">'.(int)$hop['code'].'</span> '.h($hop['from_url']).' → <a class="'.($hop['external']?'external-redirect':'').'" href="'.h($hop['to_url']).'" target="_blank" rel="noopener noreferrer">'.h($hop['to_url']).'</a></p>';
    $intro.='</section><section class="report-method"><h2>Offentlige teknologispor</h2><p>Versionsspor er ikke bekræftelse af faktisk software eller backports.</p>';
    foreach ($r['technologies'] as $name=>$meta) {
        if (in_array($name,['php','wordpress','server'],true)) $intro.='<p><strong>'.h($name).':</strong> '.h($meta['version']??$meta['signature']??'').' · '.h($meta['confidence']??'lav').' sikkerhed</p>';
        elseif ($name==='javascript') foreach ($meta as $library=>$m) $intro.='<p>'.h($library).' '.h($m['version']).' · offentligt assetspor</p>';
        elseif ($meta) $intro.='<p>'.h($name).': '.h(implode(', ',$meta)).' · navnespor, ingen verificerede sikkerhedsdata</p>';
    }
    $intro.='</section><section class="report-method"><h2>Seneste vurderinger</h2>';
    $q=$db->prepare('SELECT score,grade,assessed_at FROM security_history WHERE domain=? ORDER BY id DESC LIMIT 10'); $q->execute([$domain]);
    foreach ($q as $entry) $intro.='<p>'.h($entry['assessed_at']).' UTC · '.h($entry['grade']??'Ikke vurderbar').($entry['score']!==null?' · '.(int)$entry['score'].'/100':'').'</p>';
    $intro.='</section></div><script src="detail.js?v=0.4.0" defer></script>';
    hs_page($intro,$domain.' · HackScan');
}
