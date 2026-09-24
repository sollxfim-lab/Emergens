// ╔══════════════════════════════════════════════════════════╗
// ║  EMERGENS DASHBOARD — Full JavaScript                  ║
// ╚══════════════════════════════════════════════════════════╝

const emptyCrest = `<svg viewBox="0 0 44 44" fill="none" aria-hidden="true" class="empty-crest"><path d="M6 14V9a3 3 0 0 1 3-3h5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><path d="M38 14V9a3 3 0 0 0-3-3h-5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><path d="M6 30v5a3 3 0 0 0 3 3h5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><path d="M38 30v5a3 3 0 0 1-3 3h-5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><path d="M22 8 34.12 15 34.12 29 22 36 9.88 29 9.88 15Z" stroke="currentColor" stroke-width="2"/><circle cx="22" cy="22" r="5.4" stroke="currentColor" stroke-width="1.3"/><path d="M22 22V16.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/><circle cx="22" cy="22" r="1.4" fill="currentColor"/></svg>`;

function showToast(m,t='success'){
    const c=document.getElementById('toastContainer');
    const d=document.createElement('div');
    d.className=`toast ${t}`;
    const iconClass = t==='error' ? 'circle-xmark' : (t==='warning' ? 'star' : 'circle-check');
    d.innerHTML=`<i class="fas fa-${iconClass}"></i><span></span>`;
    d.querySelector('span').textContent=m;
    c.appendChild(d);
    setTimeout(()=>{d.classList.add('leaving');setTimeout(()=>d.remove(),250)},3000);
}
function escapeHtml(u){return String(u).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");}

// ─── LANGUAGE / i18n ───────────────────────────────────────
const translations={
    en:{
        nav_overview:"Overview",nav_testing:"Security Testing",nav_history:"Scan History",nav_console:"System Console",nav_chat:"AI Assistant",
        nav_label_data:"Data",nav_schools:"School Search",nav_label_integrations:"Integrations",nav_telegram:"Telegram Bot",
        nav_label_resources:"Resources",nav_docs:"Documentation",nav_preferences:"Preferences",nav_settings:"User Management",nav_api:"API Keys",nav_community:"Community",
        nav_label_tools:"Tools",nav_request:"API Request",nav_webps:"WebPS",nav_monitor:"Monitor",nav_quick_menu:"Quick Menu",nav_minecraft:"Minecraft Status",nav_notes:"Notes",nav_theme_studio:"Theme Studio",
        masthead_eyebrow:"Bureau Online",masthead_title:"Field Intelligence Console",
        masthead_desc:"Passive reconnaissance across WHOIS, DNS, TLS and exposure surfaces — for domains you own or are authorized to test.",
        masthead_operator:"Operator",masthead_today:"Today",
        stat_recon_tools:"Recon Tools",stat_security_modules:"Security Modules",stat_total_scans:"Total Scans",stat_system_status:"System Status",stat_online:"Online",
        quickscan_title:"Quick Scan",quickscan_desc:"Enter a domain you own or are authorized to test for a quick passive scan.",
        btn_run_quick_scan:"Run Quick Scan",recent_scans_title:"Recent Scans",loading:"Loading...",
        testing_title:"Security Testing Suite",mode_basic:"Basic Mode",mode_expert:"Expert Mode",
        testing_select_tools:"Select tools to run:",btn_start_scan:"Start Scan",
        history_title:"Scan History",history_filter_ph:"Filter by target...",
        th_target:"Target",th_mode:"Mode",th_status:"Status",th_date:"Date",th_actions:"Actions",
        stat_cpu:"CPU Usage",stat_memory:"Memory",stat_disk:"Disk",console_title:"Server Logs",
        chat_title:"AI Security Assistant",btn_clear:"Clear",chat_input_ph:"Ask about security testing...",
        schools_title:"Sekolah Search",schools_desc:"Search primary & secondary school information in Malaysia. Type a school name to see matches.",btn_search:"Search",
        tg_hero_title:"Command Emergens from Telegram",
        tg_hero_desc:"Connect a bot to receive scan results, trigger recon jobs, and manage your console straight from a Telegram chat — on your phone, desktop, or anywhere Telegram runs.",
        tg_panel_title:"Telegram Bot Integration",badge_disconnected:"Disconnected",
        tg_connect_hint:"Create a bot via <strong>@BotFather</strong> on Telegram, then paste its credentials below to link it to this console.",
        btn_connect_bot:"Connect Bot",tg_public_mode:"Public Mode",tg_public_mode_hint:"(uncheck for owner-only)",
        tg_connected_running:"Connected & Running",btn_disconnect:"Disconnect",
        tg_stat_chats:"Unique Chats",tg_stat_msgs:"Messages Today",tg_stat_mode:"Mode",tg_stat_uptime:"Uptime",
        tg_cmd_title:"Available Bot Commands",
        tg_cmd_start:"Registers this chat and shows the welcome menu.",
        tg_cmd_scan:"Runs a quick passive scan and replies with a summary.",
        tg_cmd_history:"Lists your most recent scans.",
        tg_cmd_status:"Shows console uptime and system load.",
        tg_cmd_help:"Lists every command the bot understands.",
        tg_registered_chats:"Registered Chat IDs",tg_registered_chats_hint:"(users who have sent /start)",
        tg_no_chats:"No chats yet",tg_no_chats_hint:"Users appear when they interact with the bot",
        tg_bot_settings:"Bot Settings",btn_update_owner:"Update Owner",btn_apply_mode:"Apply Mode",
        tg_broadcast_ph:"Send broadcast message to all chats...",btn_send:"Send",
        tg_step1_title:"Talk to BotFather",tg_step1_desc:"Open Telegram, message <code>@BotFather</code>, and send <code>/newbot</code>.",
        tg_step2_title:"Copy the token",tg_step2_desc:"BotFather replies with an API token — copy it exactly.",
        tg_step3_title:"Find your Chat ID",tg_step3_desc:"Message <code>@userinfobot</code> to get your numeric Chat ID for the Owner field.",
        tg_step4_title:"Connect & go",tg_step4_desc:"Paste both values below and press Connect Bot.",
        docs_title:"Documentation & Tool Guide",
        docs_intro:"A complete reference for every module in Emergens — what each tool does, what data it returns, and how to use it responsibly. Search below or browse by category.",
        docs_search_ph:"Search documentation...",
        prefs_title:"Preferences",
        prefs_desc:"Personalize how Emergens stores your data and which language the interface uses. These preferences are saved to this browser.",
        prefs_storage_title:"Data Storage",
        prefs_storage_desc:"Choose where scan history and results are kept. Server storage syncs across devices tied to your account; local storage keeps everything only in this browser and never leaves your device.",
        prefs_storage_server_title:"Server (account-synced)",prefs_storage_server_desc:"Saved to your Emergens account. Available on any device you log into.",
        prefs_storage_local_title:"Local (this browser only)",prefs_storage_local_desc:"Stored in this browser's local storage. Faster, private, but not synced anywhere.",
        btn_export_local:"Export Local History",btn_clear_local:"Clear Local Data",
        prefs_lang_title:"Interface Language",
        prefs_lang_desc:"Switch the console's menus, labels, and buttons between English and Bahasa Malaysia. Live scan data and server logs are shown exactly as returned.",
        settings_create_title:"Create Account",
        settings_create_hint:"New accounts can only be created by an Owner. A random password is generated automatically and shown once — copy it before navigating away.",
        settings_role_placeholder:"Role...",btn_create:"Create",settings_accounts_title:"Account List",
        settings_owner_notice:"Visible to Owners only — each account shows how many API keys it has generated and how many requests those keys have handled.",
        th_username:"Username",th_role:"Role",th_created:"Created",th_api_keys:"API Keys",th_view_keys:"Keys",
        userkeys_modal_empty:"This user has not generated any API keys yet.",userkeys_modal_error:"Could not load this user's key details.",userkeys_modal_loading:"Loading key details...",
        api_title:"API Keys",api_desc:"Generate and manage API keys for integrating Emergens into your CI/CD pipeline or custom tools.",
        api_stat_total_keys:"Total Keys",api_stat_total_requests:"Total Requests",api_stat_most_active:"Most Active Key",api_stat_avg_requests:"Avg. Requests / Key",
        btn_generate_key:"Generate New Key",th_key_prefix:"Key Prefix",th_last_used:"Last Used",th_requests:"Requests",
        recent_keys_title:"Recently Generated (This Browser)",
        recent_keys_desc:"Full key values are only ever shown once by the server. As a convenience, Emergens keeps a copy of keys generated on this device so you can find them again if you navigate away too fast — they never leave this browser.",
        recent_keys_empty:"No recently generated keys saved on this browser.",
        recent_keys_warning:"Stored locally on this device only. Clear this list before using a shared or public computer.",
        recent_keys_saved_label:"Saved",btn_clear_recent_keys:"Clear Saved Keys",btn_forget_key:"Forget",
        community_title:"Emergens Community",
        community_desc:"Join thousands of security professionals using Emergens. Share findings, discuss techniques, and stay updated with the latest security testing methodologies.",
        profile_stat_scans:"Scans Run",profile_stat_keys:"API Keys",profile_stat_chats:"TG Chats",
        profile_session_label:"Session started",profile_theme_label:"Theme",profile_storage_label:"Storage",btn_logout:"Log Out",
        empty_no_cases_title:"No cases opened yet",empty_no_cases_hint:"Run a quick scan above to open your first file.",
        theme_dark:"Dark",theme_light:"Light",storage_local:"Local",storage_server:"Server",
        as_username:"Username",as_role:"Role",as_expires:"Expires",as_api_keys:"API Keys",
        bn_home:"Home",bn_sec:"Sec",bn_setting:"Setting",bn_profile:"Profile",
        brat_desc:"Type a caption and generate a Brat-style cover. Works offline with a built-in renderer; if a Brat API base URL is configured it's used instead.",
        brat_input_ph:"party girl in the club...",
        briefing_video_empty:"No briefing video configured yet.",
        btn_check:"Check",btn_fetch:"Fetch",btn_generate:"Generate",btn_refresh:"Refresh",btn_save:"Save",
        reels_desc:"Search TikTok videos by keyword and preview them without leaving the console.",
        reels_search_ph:"Search TikTok videos...",
        dl_desc:"Paste a TikTok link for a watermark-free video, or switch to Pinterest Search to browse images by keyword.",
        mc_desc:"Search Minecraft Bedrock skins, mods, shaders, texture packs and more, sourced from MCPEDL.",
        mc_search_ph:"Search skins, mods, shaders...",
        gc_title:"Global Chat",gc_connecting:"Connecting…",gc_desc:"Every signed-in account sees the same conversation in real time. Tap a name to view that person's profile.",
        gc_lock_chat:"Lock Chat",gc_locked_notice:"The Owner has locked Global Chat. Only Owners can send messages right now.",gc_input_ph:"Message everyone…",
        ip_check_mine:"Check My IP",
        mc_title:"Minecraft Server Status",mc_desc:"Check whether a Minecraft server is online, its player count, MOTD and version — via the public mcstatus.io API.",
        music_desc:"Paste a link or search for a track to fetch a direct audio link.",
        nav_globalchat:"Global Chat",nav_panel_manager:"Panel Manager",nav_tools_hub:"Tools",
        net_inbound:"Inbound",net_outbound:"Outbound",net_traffic_title:"Network Traffic",net_live:"Live",
        osint_desc:"Look up public data linked to a username, email, or phone number across configured sources.",
        osint_username:"Username",osint_email:"Email",osint_number:"Number",
        pm_title:"Panel Manager",pm_desc:"Every server or client that has made a request using one of your API keys is listed here.",
        pp_title:"Change Profile Photo",pp_upload_gallery:"Upload from gallery",pp_or:"or",pp_link_ph:"https://example.com/photo.jpg",pp_use_link:"Use This Link",pp_remove:"Remove Photo",
        prayer_title:"Waktu Solat",prayer_source_note:"Times from the Aladhan API. Please cross-check against JAKIM (Malaysia) or Kemenag (Indonesia) for official reference.",
        prefs_device_title:"Device & Display",prefs_device_desc:"Emergens automatically adapts to your screen. Override it below if you'd rather force one layout.",
        prefs_device_detected:"Detected device",prefs_device_battery:"Battery",
        prefs_ui_auto:"Auto",prefs_ui_mobile:"Phone Layout",prefs_ui_desktop:"Laptop Layout",
        prefs_server_name_title:"Server / VPS Name",prefs_server_name_desc:"Set by the Owner. Visible here to every account signed in to this console.",
        settings_server_name_title:"Server / VPS Name",settings_server_name_hint:"Shown to every signed-in account under Preferences → Server/VPS Name. Leave it blank and save to hide the field for everyone.",
        th_hub_title:"Tools",th_ip:"IP",th_last_seen:"Last Seen",th_server_name:"Server Name",
        tool_brat:"Brat Generator",tool_reels:"Reels",tool_osint:"OSINT",tool_anime:"Anime",tool_wifi:"Wifi Scanner",tool_ipcheck:"IP Check",tool_quickaccess:"Quick Access",tool_music:"Music Downloader",tool_downloader:"Downloader",tool_mctools:"MCTOOLS",
        anime_search_ph:"Search anime...",
        wifi_limit_notice:"Browsers can't list nearby Wi-Fi network names on any platform — no website has that permission, for your privacy. Below is the real network &amp; location info this page can access, with your permission.",
        wifi_request_btn:"Check Network Info",
        rsb_complete:"Complete"
    },
    ms:{
        nav_overview:"Gambaran Keseluruhan",nav_testing:"Ujian Keselamatan",nav_history:"Sejarah Imbasan",nav_console:"Konsol Sistem",nav_chat:"Pembantu AI",
        nav_label_data:"Data",nav_schools:"Cari Sekolah",nav_label_integrations:"Integrasi",nav_telegram:"Bot Telegram",
        nav_label_resources:"Sumber",nav_docs:"Dokumentasi",nav_preferences:"Keutamaan",nav_settings:"Pengurusan Pengguna",nav_api:"Kunci API",nav_community:"Komuniti",
        nav_label_tools:"Alatan",nav_request:"Permintaan API",nav_webps:"WebPS",nav_monitor:"Pemantauan",nav_quick_menu:"Quick Menu",nav_minecraft:"Status Minecraft",nav_notes:"Nota",nav_theme_studio:"Studio Tema",
        masthead_eyebrow:"Biro Dalam Talian",masthead_title:"Konsol Perisikan Lapangan",
        masthead_desc:"Peninjauan pasif merentasi WHOIS, DNS, TLS dan permukaan pendedahan — untuk domain yang anda miliki atau diberi kebenaran untuk diuji.",
        masthead_operator:"Operator",masthead_today:"Hari Ini",
        stat_recon_tools:"Alat Peninjauan",stat_security_modules:"Modul Keselamatan",stat_total_scans:"Jumlah Imbasan",stat_system_status:"Status Sistem",stat_online:"Dalam Talian",
        quickscan_title:"Imbasan Pantas",quickscan_desc:"Masukkan domain yang anda miliki atau diberi kebenaran untuk diuji bagi imbasan pasif yang pantas.",
        btn_run_quick_scan:"Jalankan Imbasan Pantas",recent_scans_title:"Imbasan Terkini",loading:"Memuatkan...",
        testing_title:"Suit Ujian Keselamatan",mode_basic:"Mod Asas",mode_expert:"Mod Pakar",
        testing_select_tools:"Pilih alat untuk dijalankan:",btn_start_scan:"Mula Imbasan",
        history_title:"Sejarah Imbasan",history_filter_ph:"Tapis mengikut sasaran...",
        th_target:"Sasaran",th_mode:"Mod",th_status:"Status",th_date:"Tarikh",th_actions:"Tindakan",
        stat_cpu:"Penggunaan CPU",stat_memory:"Memori",stat_disk:"Cakera",console_title:"Log Pelayan",
        chat_title:"Pembantu Keselamatan AI",btn_clear:"Kosongkan",chat_input_ph:"Tanya tentang ujian keselamatan...",
        schools_title:"Carian Sekolah",schools_desc:"Cari maklumat sekolah rendah & menengah di Malaysia. Taip nama sekolah untuk melihat padanan.",btn_search:"Cari",
        tg_hero_title:"Kawal Emergens Terus Dari Telegram",
        tg_hero_desc:"Sambungkan bot untuk menerima keputusan imbasan, mencetuskan tugasan peninjauan, dan mengurus konsol anda terus dari sembang Telegram — di telefon, komputer, atau di mana sahaja Telegram berjalan.",
        tg_panel_title:"Integrasi Bot Telegram",badge_disconnected:"Tidak Disambung",
        tg_connect_hint:"Cipta bot melalui <strong>@BotFather</strong> di Telegram, kemudian tampal kelayakannya di bawah untuk menyambungkannya ke konsol ini.",
        btn_connect_bot:"Sambung Bot",tg_public_mode:"Mod Awam",tg_public_mode_hint:"(nyahtanda untuk pemilik sahaja)",
        tg_connected_running:"Disambung & Berjalan",btn_disconnect:"Putuskan Sambungan",
        tg_stat_chats:"Sembang Unik",tg_stat_msgs:"Mesej Hari Ini",tg_stat_mode:"Mod",tg_stat_uptime:"Masa Aktif",
        tg_cmd_title:"Arahan Bot Yang Tersedia",
        tg_cmd_start:"Mendaftarkan sembang ini dan memaparkan menu selamat datang.",
        tg_cmd_scan:"Menjalankan imbasan pasif pantas dan membalas dengan ringkasan.",
        tg_cmd_history:"Menyenaraikan imbasan terkini anda.",
        tg_cmd_status:"Memaparkan masa aktif konsol dan beban sistem.",
        tg_cmd_help:"Menyenaraikan semua arahan yang difahami oleh bot.",
        tg_registered_chats:"ID Sembang Berdaftar",tg_registered_chats_hint:"(pengguna yang telah menghantar /start)",
        tg_no_chats:"Belum ada sembang",tg_no_chats_hint:"Pengguna akan muncul apabila mereka berinteraksi dengan bot",
        tg_bot_settings:"Tetapan Bot",btn_update_owner:"Kemas Kini Pemilik",btn_apply_mode:"Guna Pakai Mod",
        tg_broadcast_ph:"Hantar mesej siaran ke semua sembang...",btn_send:"Hantar",
        tg_step1_title:"Hubungi BotFather",tg_step1_desc:"Buka Telegram, hantar mesej kepada <code>@BotFather</code>, dan taip <code>/newbot</code>.",
        tg_step2_title:"Salin token",tg_step2_desc:"BotFather akan membalas dengan token API — salin dengan tepat.",
        tg_step3_title:"Cari ID Sembang anda",tg_step3_desc:"Hantar mesej kepada <code>@userinfobot</code> untuk dapatkan ID Sembang berangka anda bagi ruangan Pemilik.",
        tg_step4_title:"Sambung & mula",tg_step4_desc:"Tampal kedua-dua nilai di bawah dan tekan Sambung Bot.",
        docs_title:"Dokumentasi & Panduan Alat",
        docs_intro:"Rujukan lengkap untuk setiap modul dalam Emergens — apa yang dilakukan oleh setiap alat, data yang dikembalikan, dan cara menggunakannya secara bertanggungjawab. Cari di bawah atau layari mengikut kategori.",
        docs_search_ph:"Cari dokumentasi...",
        prefs_title:"Keutamaan",
        prefs_desc:"Sesuaikan cara Emergens menyimpan data anda dan bahasa antara muka yang digunakan. Keutamaan ini disimpan pada pelayar ini.",
        prefs_storage_title:"Penyimpanan Data",
        prefs_storage_desc:"Pilih di mana sejarah dan keputusan imbasan disimpan. Penyimpanan pelayan menyegerak merentasi peranti yang terikat dengan akaun anda; penyimpanan tempatan menyimpan semuanya hanya dalam pelayar ini dan tidak pernah meninggalkan peranti anda.",
        prefs_storage_server_title:"Pelayan (segerak akaun)",prefs_storage_server_desc:"Disimpan ke akaun Emergens anda. Boleh diakses pada mana-mana peranti yang anda log masuk.",
        prefs_storage_local_title:"Tempatan (pelayar ini sahaja)",prefs_storage_local_desc:"Disimpan dalam storan tempatan pelayar ini. Lebih pantas, peribadi, tetapi tidak disegerakkan ke mana-mana.",
        btn_export_local:"Eksport Sejarah Tempatan",btn_clear_local:"Kosongkan Data Tempatan",
        prefs_lang_title:"Bahasa Antara Muka",
        prefs_lang_desc:"Tukar menu, label, dan butang konsol antara Bahasa Inggeris dan Bahasa Malaysia. Data imbasan langsung dan log pelayan dipaparkan sepertimana ia dikembalikan.",
        settings_create_title:"Cipta Akaun",
        settings_create_hint:"Akaun baharu hanya boleh dicipta oleh Pemilik. Kata laluan rawak dijana secara automatik dan dipaparkan sekali sahaja — salin sebelum meninggalkan halaman ini.",
        settings_role_placeholder:"Peranan...",btn_create:"Cipta",settings_accounts_title:"Senarai Akaun",
        settings_owner_notice:"Hanya kelihatan kepada Pemilik — setiap akaun memaparkan berapa banyak kunci API yang telah dijana dan berapa banyak permintaan yang dikendalikan oleh kunci tersebut.",
        th_username:"Nama Pengguna",th_role:"Peranan",th_created:"Dicipta",th_api_keys:"Kunci API",th_view_keys:"Kunci",
        userkeys_modal_empty:"Pengguna ini belum menjana sebarang kunci API.",userkeys_modal_error:"Tidak dapat memuatkan butiran kunci pengguna ini.",userkeys_modal_loading:"Memuatkan butiran kunci...",
        api_title:"Kunci API",api_desc:"Jana dan urus kunci API untuk mengintegrasikan Emergens ke dalam saluran CI/CD atau alat tersuai anda.",
        api_stat_total_keys:"Jumlah Kunci",api_stat_total_requests:"Jumlah Permintaan",api_stat_most_active:"Kunci Paling Aktif",api_stat_avg_requests:"Purata Permintaan / Kunci",
        btn_generate_key:"Jana Kunci Baharu",th_key_prefix:"Awalan Kunci",th_last_used:"Digunakan Terakhir",th_requests:"Permintaan",
        recent_keys_title:"Baru Dijana (Pelayar Ini)",
        recent_keys_desc:"Nilai penuh kunci hanya dipaparkan sekali oleh pelayan. Sebagai kemudahan, Emergens menyimpan salinan kunci yang dijana pada peranti ini supaya anda boleh mencarinya semula jika terlalu pantas beralih halaman — ia tidak pernah meninggalkan pelayar ini.",
        recent_keys_empty:"Tiada kunci baru dijana disimpan pada pelayar ini.",
        recent_keys_warning:"Disimpan secara tempatan pada peranti ini sahaja. Kosongkan senarai ini sebelum menggunakan komputer awam atau dikongsi.",
        recent_keys_saved_label:"Disimpan",btn_clear_recent_keys:"Kosongkan Kunci Disimpan",btn_forget_key:"Lupakan",
        community_title:"Komuniti Emergens",
        community_desc:"Sertai beribu-ribu profesional keselamatan yang menggunakan Emergens. Kongsi penemuan, bincangkan teknik, dan kekal terkini dengan metodologi ujian keselamatan terkini.",
        profile_stat_scans:"Imbasan Dijalankan",profile_stat_keys:"Kunci API",profile_stat_chats:"Sembang TG",
        profile_session_label:"Sesi bermula",profile_theme_label:"Tema",profile_storage_label:"Penyimpanan",btn_logout:"Log Keluar",
        empty_no_cases_title:"Belum ada kes dibuka",empty_no_cases_hint:"Jalankan imbasan pantas di atas untuk membuka fail pertama anda.",
        theme_dark:"Gelap",theme_light:"Cerah",storage_local:"Tempatan",storage_server:"Pelayan",
        as_username:"Nama Pengguna",as_role:"Peranan",as_expires:"Tamat Tempoh",as_api_keys:"Kunci API",
        bn_home:"Utama",bn_sec:"Keselamatan",bn_setting:"Tetapan",bn_profile:"Profil",
        brat_desc:"Taip kapsyen dan jana kulit gaya Brat. Berfungsi secara luar talian dengan penjana terbina dalam; jika URL API Brat dikonfigurasi, ia akan digunakan.",
        brat_input_ph:"party girl in the club...",
        briefing_video_empty:"Belum ada video taklimat dikonfigurasikan.",
        btn_check:"Semak",btn_fetch:"Ambil",btn_generate:"Jana",btn_refresh:"Muat Semula",btn_save:"Simpan",
        reels_desc:"Cari video TikTok mengikut kata kunci dan pratonton terus dalam konsol ini.",
        reels_search_ph:"Cari video TikTok...",
        dl_desc:"Tampal pautan TikTok untuk video tanpa tera air, atau tukar ke Carian Pinterest untuk cari imej mengikut kata kunci.",
        mc_desc:"Cari skin, mod, shader, texture pack Minecraft Bedrock dan banyak lagi, daripada sumber MCPEDL.",
        mc_search_ph:"Cari skin, mod, shader...",
        gc_title:"Sembang Global",gc_connecting:"Menyambung…",gc_desc:"Setiap akaun yang log masuk melihat perbualan yang sama secara masa nyata. Ketik nama untuk lihat profil orang itu.",
        gc_lock_chat:"Kunci Sembang",gc_locked_notice:"Owner telah mengunci Sembang Global. Hanya Owner boleh menghantar mesej sekarang.",gc_input_ph:"Mesej semua orang…",
        ip_check_mine:"Semak IP Saya",
        mc_title:"Status Server Minecraft",mc_desc:"Semak sama ada server Minecraft dalam talian, bilangan pemain, MOTD dan versi — melalui API awam mcstatus.io.",
        music_desc:"Tampal pautan atau cari lagu untuk dapatkan pautan audio terus.",
        nav_globalchat:"Sembang Global",nav_panel_manager:"Pengurus Panel",nav_tools_hub:"Alatan",
        net_inbound:"Masuk",net_outbound:"Keluar",net_traffic_title:"Trafik Rangkaian",net_live:"Langsung",
        osint_desc:"Cari data awam yang berkaitan dengan nama pengguna, emel, atau nombor telefon merentasi sumber yang dikonfigurasi.",
        osint_username:"Nama Pengguna",osint_email:"Emel",osint_number:"Nombor",
        pm_title:"Pengurus Panel",pm_desc:"Setiap server atau klien yang membuat permintaan menggunakan salah satu kunci API anda disenaraikan di sini.",
        pp_title:"Tukar Foto Profil",pp_upload_gallery:"Muat Naik dari Galeri",pp_or:"atau",pp_link_ph:"https://example.com/photo.jpg",pp_use_link:"Guna Pautan Ini",pp_remove:"Buang Foto",
        prayer_title:"Waktu Solat",prayer_source_note:"Waktu daripada API Aladhan. Sila semak semula dengan JAKIM (Malaysia) atau Kemenag (Indonesia) untuk rujukan rasmi.",
        prefs_device_title:"Peranti &amp; Paparan",prefs_device_desc:"Emergens menyesuaikan diri secara automatik dengan skrin anda. Ubah di bawah jika anda mahu paksa satu susun atur.",
        prefs_device_detected:"Peranti Dikesan",prefs_device_battery:"Bateri",
        prefs_ui_auto:"Auto",prefs_ui_mobile:"Susun Atur Telefon",prefs_ui_desktop:"Susun Atur Laptop",
        prefs_server_name_title:"Nama Server / VPS",prefs_server_name_desc:"Ditetapkan oleh Owner. Kelihatan di sini untuk setiap akaun yang log masuk ke konsol ini.",
        settings_server_name_title:"Nama Server / VPS",settings_server_name_hint:"Dipaparkan kepada setiap akaun yang log masuk di bawah Keutamaan → Nama Server/VPS. Biarkan kosong dan simpan untuk sembunyikan medan ini untuk semua orang.",
        th_hub_title:"Alatan",th_ip:"IP",th_last_seen:"Kali Terakhir Dilihat",th_server_name:"Nama Server",
        tool_brat:"Penjana Brat",tool_reels:"Reels",tool_osint:"OSINT",tool_anime:"Anime",tool_wifi:"Pengimbas Wifi",tool_ipcheck:"Semak IP",tool_quickaccess:"Akses Pantas",tool_music:"Downloader Muzik",tool_downloader:"Downloader",tool_mctools:"MCTOOLS",
        anime_search_ph:"Cari anime...",
        wifi_limit_notice:"Pelayar tidak boleh menyenaraikan nama rangkaian Wi-Fi berdekatan pada mana-mana platform — tiada laman web mempunyai kebenaran itu, demi privasi anda. Di bawah ialah maklumat rangkaian &amp; lokasi sebenar yang boleh diakses oleh halaman ini, dengan kebenaran anda.",
        wifi_request_btn:"Semak Maklumat Rangkaian",
        rsb_complete:"Selesai"
    }
};
let currentLang=localStorage.getItem('emergens-lang')||'en';
function t(key){return (translations[currentLang]&&translations[currentLang][key]!==undefined)?translations[currentLang][key]:(translations.en[key]!==undefined?translations.en[key]:key);}
function initLangUI(){
    const pillEn=document.getElementById('langPillEn'),pillMs=document.getElementById('langPillMs'),lbl=document.getElementById('langToggleLabel');
    if(pillEn)pillEn.classList.toggle('active',currentLang==='en');
    if(pillMs)pillMs.classList.toggle('active',currentLang==='ms');
    if(lbl)lbl.textContent=currentLang==='en'?'EN':'BM';
}
function applyLanguage(lang,scope){
    if(lang)currentLang=lang;
    localStorage.setItem('emergens-lang',currentLang);
    const root=scope||document;
    root.querySelectorAll('[data-i18n]').forEach(el=>{
        const k=el.getAttribute('data-i18n');
        const val=translations[currentLang]&&translations[currentLang][k];
        if(val===undefined)return;
        if(el.hasAttribute('data-i18n-html'))el.innerHTML=val;else el.textContent=val;
    });
    root.querySelectorAll('[data-i18n-ph]').forEach(el=>{
        const k=el.getAttribute('data-i18n-ph');
        const val=translations[currentLang]&&translations[currentLang][k];
        if(val!==undefined)el.setAttribute('placeholder',val);
    });
    initLangUI();
    const activeNav=document.querySelector('.nav-item.active');
    if(activeNav)document.getElementById('pageTitle').textContent=activeNav.textContent.trim();
    if(typeof renderTelegramSteps==='function')renderTelegramSteps();
    if(typeof renderDocs==='function')renderDocs(document.getElementById('docsSearchInput')?document.getElementById('docsSearchInput').value:'');
}
function setLanguage(lang){applyLanguage(lang);showToast(lang==='en'?'Language set to English.':'Bahasa dialihkan ke Bahasa Malaysia.');}

// ─── STORAGE PREFERENCE (server vs local) ──────────────────
const LOCAL_HISTORY_KEY='emergens-local-history';
function getStoragePref(){return localStorage.getItem('emergens-storage-pref')||'server';}
function setStoragePref(v){localStorage.setItem('emergens-storage-pref',v);}
function getLocalHistory(){try{return JSON.parse(localStorage.getItem(LOCAL_HISTORY_KEY)||'[]');}catch(e){return[];}}
function setLocalHistory(arr){localStorage.setItem(LOCAL_HISTORY_KEY,JSON.stringify(arr));}
function addLocalHistoryEntry(entry){const arr=getLocalHistory();arr.unshift(entry);setLocalHistory(arr);}
function removeLocalHistoryEntry(id){const arr=getLocalHistory().filter(e=>String(e.id)!==String(id));setLocalHistory(arr);}
function initStorageChoice(){
    const pref=getStoragePref();
    const s=document.getElementById('storageChoiceServer'),l=document.getElementById('storageChoiceLocal');
    if(s)s.classList.toggle('selected',pref==='server');
    if(l)l.classList.toggle('selected',pref==='local');
}

// ─── THEME ─────────────────────────────────────────────────
(function(){
    const r=document.documentElement;
    const s=localStorage.getItem('emergens-theme')||'dark';
    r.setAttribute('data-theme',s);
    function u(){
        const b=document.getElementById('themeToggle');
        if(!b)return;
        b.querySelector('i').className=r.getAttribute('data-theme')==='dark'?'fas fa-moon':'fas fa-sun';
    }
    document.getElementById('themeToggle').addEventListener('click',()=>{
        const n=r.getAttribute('data-theme')==='dark'?'light':'dark';
        r.setAttribute('data-theme',n);
        localStorage.setItem('emergens-theme',n);
        u();
    });
    u();
})();

// ─── NAVIGATION ────────────────────────────────────────────
const N=document.querySelectorAll('.nav-item'),
      S=document.querySelectorAll('.content-section'),
      T=document.getElementById('pageTitle'),
      SB=document.getElementById('sidebar');

N.forEach(b=>b.addEventListener('click',(e)=>{
    if(!b.dataset.section)return; // plain external links (Tools group) just navigate normally
    N.forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    const sec=b.dataset.section;
    S.forEach(s=>s.classList.toggle('active',s.id===`section-${sec}`));
    T.textContent=b.textContent.trim();
    if(window.innerWidth<900)SB.classList.remove('open');
    window.dispatchEvent(new CustomEvent('section-change',{detail:sec}));
}));

document.getElementById('mobileMenuBtn').addEventListener('click',()=>SB.classList.toggle('open'));
document.addEventListener('click',e=>{
    if(window.innerWidth>=900||!SB.classList.contains('open'))return;
    if(!SB.contains(e.target)&&e.target!==document.getElementById('mobileMenuBtn'))SB.classList.remove('open');
});

document.getElementById('logoutBtn').addEventListener('click',async()=>{
    try{await fetch('/api/logout',{method:'POST'})}catch(e){}
    window.location.href='/login.html';
});

function updateMastheadDate(){
    const e=document.getElementById('mastheadDate');
    if(e)e.textContent=new Date().toLocaleDateString('en-US',{weekday:'long',month:'long',day:'numeric',year:'numeric'});
}
updateMastheadDate();

document.getElementById('langToggle').addEventListener('click',()=>setLanguage(currentLang==='en'?'ms':'en'));

// ─── AUTH + PROFILE ────────────────────────────────────────
let currentUserRole='';
let currentUsername='';
let currentUserExpiry=null;
let currentAvatarUrl=null;
const sessionStartTime=new Date();
async function loadMe(){
    try{
        const r=await fetch('/api/me');
        if(!r.ok)return;
        const d=await r.json();
        currentUsername=d.username||'';
        document.getElementById('sidebarUsername').textContent=d.username||'--';
        document.getElementById('sidebarRole').textContent=d.role||'--';
        document.getElementById('mastheadOperator').textContent=d.username||'--';
        currentUserRole=d.role||'';
        currentUserExpiry = d.expires_at ?? d.expiry ?? d.expires ?? d.subscription_expires ?? null;
        currentAvatarUrl = d.avatar_url ?? d.photo_url ?? d.avatar ?? d.profile_photo ?? null;
        const initial=(d.username||'?').trim().charAt(0).toUpperCase()||'?';
        const avatarEl=document.getElementById('sidebarAvatarInitial');
        if(avatarEl)avatarEl.textContent=initial;
        applyAvatarEverywhere(currentAvatarUrl, initial);
        renderAccountSummary(d);
        renderBriefingHeader();
        applyRoleRestrictions();
    }catch(e){}
}
function renderAccountSummary(d){
    d = d || {username:currentUsername, role:currentUserRole};
    const u=document.getElementById('asUsername'), r=document.getElementById('asRole'),
          x=document.getElementById('asExpires'), k=document.getElementById('asApiKeys');
    if(u)u.textContent=d.username||'--';
    if(r)r.textContent=d.role||'--';
    if(x){
        if(currentUserExpiry){
            const dt=new Date(currentUserExpiry);
            x.textContent = isNaN(dt.getTime()) ? String(currentUserExpiry) : dt.toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'});
        }else{
            x.textContent='Never';
        }
    }
    if(k)k.textContent = (typeof currentApiKeyCount==='number' && currentApiKeyCount>0) ? String(currentApiKeyCount) : (currentApiKeyCount===0?'0':'--');
}
function renderBriefingHeader(){
    const u=document.getElementById('briefingUsername'), r=document.getElementById('briefingRole');
    if(u)u.textContent=currentUsername||'--';
    if(r)r.innerHTML=`<i class="fas fa-shield-halved"></i> ${escapeHtml(currentUserRole||'--')}`;
}
function applyAvatarEverywhere(url, initial){
    // Sidebar avatar
    const sideCore=document.getElementById('sidebarAvatarInitial');
    if(sideCore){
        if(url){ sideCore.innerHTML=`<img src="${escapeHtml(url)}" alt="">`; }
        else { sideCore.textContent=initial; }
    }
    // Profile modal avatar
    const profCore=document.getElementById('profileAvatarInitial');
    if(profCore){
        if(url){ profCore.innerHTML=`<img src="${escapeHtml(url)}" alt="">`; }
        else { profCore.textContent=initial; }
    }
}
function applyRoleRestrictions(){
    const ownerOnlyNav=document.querySelectorAll('.owner-only');
    const ownerSections=document.querySelectorAll('.owner-section');
    if(currentUserRole!=='owner'){
        ownerOnlyNav.forEach(n=>n.style.display='none');
        ownerSections.forEach(s=>s.style.display='none');
    }else{
        ownerOnlyNav.forEach(n=>n.style.display='');
        ownerSections.forEach(s=>s.style.display='');
    }
}
loadMe();

function openProfileModal(){
    document.getElementById('profileModalName').textContent=document.getElementById('sidebarUsername').textContent||'--';
    document.getElementById('profileModalRole').innerHTML=`<i class="fas fa-shield-halved"></i> ${document.getElementById('sidebarRole').textContent||'--'}`;
    const uname=document.getElementById('sidebarUsername').textContent||'?';
    const initial=uname.trim().charAt(0).toUpperCase()||'?';
    document.getElementById('profileAvatarInitial').textContent=initial;
    document.getElementById('profileStatScans').textContent=document.getElementById('totalScansCount').textContent||'--';
    document.getElementById('profileStatKeys').textContent=(typeof currentApiKeyCount!=='undefined')?currentApiKeyCount:'--';
    const chatCountEl=document.getElementById('telegramChatCount');
    document.getElementById('profileStatChats').textContent=chatCountEl?chatCountEl.textContent:'0';
    document.getElementById('profileSessionTime').textContent=sessionStartTime.toLocaleTimeString();
    document.getElementById('profileThemeValue').textContent=document.documentElement.getAttribute('data-theme')==='dark'?t('theme_dark'):t('theme_light');
    document.getElementById('profileStorageValue').textContent=getStoragePref()==='local'?t('storage_local'):t('storage_server');
    document.getElementById('profileModalOverlay').hidden=false;
}
function closeProfileModal(){document.getElementById('profileModalOverlay').hidden=true;}
document.getElementById('sidebarProfileTrigger').addEventListener('click',openProfileModal);
document.getElementById('sidebarProfileTrigger').addEventListener('keydown',(e)=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();openProfileModal();}});
document.getElementById('profileModalClose').addEventListener('click',closeProfileModal);
document.getElementById('profileModalOverlay').addEventListener('click',function(e){if(e.target===this)closeProfileModal();});
document.addEventListener('keydown',function(e){if(e.key==='Escape'&&!document.getElementById('profileModalOverlay').hidden)closeProfileModal();});
document.getElementById('profileSignoutBtn').addEventListener('click',()=>{document.getElementById('logoutBtn').click();});

// ─── TOOLS ─────────────────────────────────────────────────
let toolsMap={};
// ── METHOD CAROUSEL ──────────────────────────────────────────────
// Color and metadata for every known tool key. Unknown keys fall back to indigo.
const METHOD_META = {
    whois_lookup:      { color:'#06b6d4', icon:'fa-id-card',      badge:'Recon',   desc:'Query WHOIS registries to reveal domain registrar, owner, creation and expiry dates, and DNS nameservers.', usage:'Mode: Basic+Expert\nOutput: Registrar, owner contacts, dates, NS records' },
    dns_lookup:        { color:'#8b5cf6', icon:'fa-server',        badge:'Network', desc:'Resolve A, AAAA, MX, TXT, CNAME, NS and SOA records for the target domain via public resolvers.', usage:'Mode: Basic+Expert\nOutput: All DNS record types, TTL values' },
    ssl_check:         { color:'#10b981', icon:'fa-lock',          badge:'TLS',     desc:'Inspect the TLS/SSL certificate chain for expiry, validity, issuer trust and weak cipher suites.', usage:'Mode: Basic+Expert\nOutput: Cert chain, expiry, grade, weak ciphers' },
    headers_check:     { color:'#f59e0b', icon:'fa-heading',       badge:'HTTP',    desc:'Fetch HTTP response headers and audit for missing security directives (CSP, HSTS, X-Frame-Options, etc.).', usage:'Mode: Basic+Expert\nOutput: Present/missing headers, risk rating' },
    ip_info:           { color:'#6366f1', icon:'fa-network-wired', badge:'Network', desc:'Geolocate the target IP, identify ASN and hosting provider, and check against abuse/blocklists.', usage:'Mode: Basic+Expert\nOutput: Country, ASN, ISP, abuse score, lat/lon' },
    connectivity_check:{ color:'#14b8a6', icon:'fa-wifi',          badge:'Recon',   desc:'Verify that the target host is reachable over HTTP/HTTPS and measure response time and redirect chains.', usage:'Mode: Basic+Expert\nOutput: HTTP status, redirect chain, latency ms' },
    email_security:    { color:'#ec4899', icon:'fa-envelope-circle-check', badge:'Mail', desc:'Check SPF, DKIM and DMARC records to assess the domain\'s email authentication posture.', usage:'Mode: Basic+Expert\nOutput: SPF policy, DKIM selector, DMARC action' },
    subdomain_enum:    { color:'#f97316', icon:'fa-sitemap',       badge:'Recon',   desc:'Enumerate subdomains via certificate transparency logs, DNS brute-force and passive OSINT sources.', usage:'Mode: Basic+Expert\nOutput: Discovered subdomains, resolved IPs' },
    tech_fingerprint:  { color:'#a855f7', icon:'fa-fingerprint',   badge:'Recon',   desc:'Identify web server, frameworks, CMS, CDN, JavaScript libraries and their versions via passive analysis.', usage:'Mode: Basic+Expert\nOutput: CMS, server, frameworks, trackers' },
    port_scan:         { color:'#3b82f6', icon:'fa-plug',          badge:'Network', desc:'Scan the top 1 000 TCP ports using SYN probes to discover open services and running daemons.', usage:'Mode: Basic+Expert\nOutput: Open ports, detected service banners' },
    sql_map:           { color:'#ef4444', icon:'fa-database',      badge:'Injection',desc:'Automated detection of SQL injection vulnerabilities using error-based, boolean-blind and time-blind techniques.', usage:'Mode: Expert only\nOutput: Injectable params, DB type, extracted data preview' },
    xss:               { color:'#dc2626', icon:'fa-code',          badge:'Injection',desc:'Test for reflected and stored XSS by injecting HTML/JS payloads into URL parameters, forms and headers.', usage:'Mode: Expert only\nOutput: Vulnerable endpoints, effective payload strings' },
    api_scanner:       { color:'#0ea5e9', icon:'fa-key',           badge:'API',     desc:'Probe REST endpoints for auth bypass, IDOR, rate limiting and information disclosure via fuzzing.', usage:'Mode: Expert only\nOutput: Vulnerable routes, missing auth gates' },
    lfi_rfi:           { color:'#ca8a04', icon:'fa-folder-open',   badge:'Injection',desc:'Test for Local/Remote File Inclusion by injecting path traversal sequences and remote URL payloads.', usage:'Mode: Expert only\nOutput: Included file contents, server paths' },
    ssrf:              { color:'#be185d', icon:'fa-arrows-to-circle', badge:'Logic', desc:'Detect Server-Side Request Forgery by tricking the server into making requests to internal or external destinations.', usage:'Mode: Expert only\nOutput: Reachable internal IPs/services, data exfiltrated' },
};

function buildMethodCarousel(toolsMap){
    const carousel = document.getElementById('methodCarousel');
    const dots = document.getElementById('methodDots');
    const hiddenList = document.getElementById('toolChecklist');
    if(!carousel) return;

    // Sync: each carousel card drives a hidden checkbox for scan submission
    hiddenList.innerHTML = Object.keys(toolsMap).map(k=>
        `<label class="tool-check"><input type="checkbox" value="${k}" checked><span class="tool-switch" aria-hidden="true"></span><div><div class="tool-name">${escapeHtml(toolsMap[k].name||k)}</div></div></label>`
    ).join('');

    const entries = Object.entries(toolsMap);
    carousel.innerHTML = entries.map(([key, tool]) => {
        const meta = METHOD_META[key] || { color:'#6366f1', icon:'fa-magnifying-glass', badge:'Tool', desc: tool.description||tool.desc||'Run this security check against the target.', usage:'Mode: Basic+Expert\nOutput: Detailed findings report' };
        return `
        <div class="method-card" data-key="${escapeHtml(key)}" style="--method-color:${meta.color}">
            <div class="method-card-header">
                <div class="method-card-icon"><i class="fas ${meta.icon}"></i></div>
                <div class="method-card-check"><i class="fas fa-check"></i></div>
            </div>
            <div>
                <div class="method-card-name">${escapeHtml(tool.name||key)}</div>
                <div class="method-card-badge">${meta.badge}</div>
            </div>
            <div class="method-card-desc">${escapeHtml(meta.desc)}</div>
            <div class="method-card-usage"><strong>Details</strong>${escapeHtml(meta.usage)}</div>
        </div>`;
    }).join('');

    // Dots
    dots.innerHTML = entries.map((_,i)=>
        `<button class="method-dot${i===0?' active':''}" data-index="${i}" aria-label="Go to method ${i+1}"></button>`
    ).join('');

    // Mark all selected by default (sync with hidden checkboxes)
    carousel.querySelectorAll('.method-card').forEach(card => card.classList.add('selected'));

    // Click: toggle selection + sync hidden checkbox
    carousel.addEventListener('click', e => {
        const card = e.target.closest('.method-card');
        if(!card) return;
        card.classList.toggle('selected');
        const key = card.dataset.key;
        const cb = hiddenList.querySelector(`input[value="${key}"]`);
        if(cb) cb.checked = card.classList.contains('selected');
    });

    // Dots navigation
    dots.addEventListener('click', e => {
        const btn = e.target.closest('.method-dot');
        if(!btn) return;
        const idx = parseInt(btn.dataset.index);
        const cards = carousel.querySelectorAll('.method-card');
        if(cards[idx]) cards[idx].scrollIntoView({ behavior:'smooth', inline:'start', block:'nearest' });
    });

    // Arrow nav
    const prev = document.getElementById('methodNavPrev');
    const next = document.getElementById('methodNavNext');
    let currentIdx = 0;
    function scrollToIdx(idx){
        const cards = carousel.querySelectorAll('.method-card');
        idx = Math.max(0, Math.min(idx, cards.length-1));
        currentIdx = idx;
        cards[idx].scrollIntoView({ behavior:'smooth', inline:'start', block:'nearest' });
    }
    if(prev) prev.addEventListener('click', ()=> scrollToIdx(currentIdx-1));
    if(next) next.addEventListener('click', ()=> scrollToIdx(currentIdx+1));

    // Update active dot on scroll
    const io = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if(entry.isIntersecting && entry.intersectionRatio >= 0.5){
                const allCards = [...carousel.querySelectorAll('.method-card')];
                const idx = allCards.indexOf(entry.target);
                if(idx < 0) return;
                currentIdx = idx;
                dots.querySelectorAll('.method-dot').forEach((d,i)=>d.classList.toggle('active', i===idx));
            }
        });
    }, { root: carousel, threshold: 0.5 });
    carousel.querySelectorAll('.method-card').forEach(c => io.observe(c));
}

async function loadTools(){
    try{
        const r = await fetch('/api/tools');
        const d = await r.json();
        const tools = d.tools || d;
        if(Array.isArray(tools)){
            toolsMap = {};
            tools.forEach(t => { toolsMap[t] = { name: t, description: METHOD_META[t]?.desc || '' }; });
        } else {
            toolsMap = tools;
        }
        buildMethodCarousel(toolsMap);
        document.getElementById('toolsCount').textContent = Object.keys(toolsMap).length || '--';
    } catch(e){
        const carousel = document.getElementById('methodCarousel');
        if(carousel) carousel.innerHTML = '<div class="empty-state"><i class="fas fa-circle-exclamation"></i> Could not load tools from server.</div>';
    }
}
loadTools();

// ─── OVERVIEW ──────────────────────────────────────────────
async function refreshOverview(){
    try{
        let arr;
        if(getStoragePref()==='local'){
            arr=getLocalHistory();
        }else{
            const r=await fetch('/api/history');const h=await r.json();arr=Array.isArray(h)?h:[];
        }
        document.getElementById('totalScansCount').textContent=arr.length;
        const c=document.getElementById('recentScansList');
        const recent=arr.slice(0,5);
        if(!recent.length){
            c.innerHTML=`<div class="empty-state">${emptyCrest}<strong data-i18n="empty_no_cases_title">No cases opened yet</strong><span class="hint" data-i18n="empty_no_cases_hint">Run a quick scan above to open your first file.</span></div>`;
            applyLanguage(null,c);
            return;
        }
        c.innerHTML=recent.map(r=>`<div class="recent-scan-row"><span class="case-tag">№${String(r.id).padStart(4,'0')}</span><div class="recent-scan-target"><i class="fas fa-globe"></i>${r.target}</div><span class="badge">${r.mode||'basic'}</span><span class="badge success">${r.status||'completed'}</span><span class="recent-scan-date">${new Date(r.created_at).toLocaleString()}</span></div>`).join('');
    }catch(e){
        document.getElementById('recentScansList').innerHTML='<div class="empty-state">Could not load recent scans.</div>';
    }
}
refreshOverview();

// ─── SCAN ENGINE ───────────────────────────────────────────
// Every scan-progress "instance" below is a set of element-id prefixes. Both
// the Testing page's original progress card and the Overview page's compact
// one are kept in sync from the same poll loop, so a scan is always visible
// wherever the person started it from — and if they switch pages mid-scan,
// whichever card is now on screen is still accurate.
const scanPhases=["Scanning . . .","Analytic data . . .","Analysis sub domain . . .","Scanning critical data . . ."];
const SCAN_UI_INSTANCES=[
    { wrap:'scanProgressWrap', card:'scanProgressCard', fill:'scanProgressFill', pct:'scanProgressPct', label:'scanProgressLabel', elapsed:'scanElapsed', phaseWrap:'scanPhaseWrapper', phaseText:'scanPhaseText', stepper:'scanStepper' },
    { wrap:'ovScanProgressWrap', card:'ovScanProgressCard', fill:'ovScanProgressFill', pct:'ovScanProgressPct', label:'ovScanProgressLabel', elapsed:'ovScanElapsed', phaseWrap:'ovScanPhaseWrapper', phaseText:'ovScanPhaseText', stepper:'ovScanStepper' }
];
function forEachScanUi(fn){
    SCAN_UI_INSTANCES.forEach(inst=>{
        const wrapEl=document.getElementById(inst.wrap);
        if(!wrapEl)return; // this particular popup/page instance isn't in the DOM
        fn(inst,wrapEl);
    });
}
function updateScanPhase(p){
    const i=Math.min(Math.floor(p/25),scanPhases.length-1);
    forEachScanUi(inst=>{
        const el=document.getElementById(inst.phaseText);
        if(el)el.textContent=scanPhases[i];
    });
    updateScanStepper(p);
}
function resetScanStepper(){
    forEachScanUi(inst=>{
        document.querySelectorAll(`#${inst.stepper} .scan-step`).forEach((s,i)=>{s.classList.remove('active','done');const n=s.querySelector('.scan-step-node');if(n)n.textContent=(i+1);});
        document.querySelectorAll(`#${inst.stepper} .scan-step-line`).forEach(l=>l.classList.remove('done'));
    });
}
function updateScanStepper(pct){
    forEachScanUi(inst=>{
        const steps=document.querySelectorAll(`#${inst.stepper} .scan-step`);
        const lines=document.querySelectorAll(`#${inst.stepper} .scan-step-line`);
        if(!steps.length)return;
        const activeIdx=Math.min(Math.floor(pct/25),steps.length-1);
        steps.forEach((s,i)=>{
            s.classList.remove('active','done');
            const node=s.querySelector('.scan-step-node');
            if(i<activeIdx||pct>=100){s.classList.add('done');node.innerHTML='<i class="fas fa-check"></i>';}
            else if(i===activeIdx){s.classList.add('active');node.innerHTML='<i class="fas fa-circle-notch fa-spin"></i>';}
            else{node.textContent=(i+1);}
        });
        lines.forEach((l,i)=>{l.classList.toggle('done',i<activeIdx||pct>=100);});
    });
}
function resetProgressUI(){
    forEachScanUi((inst,wrapEl)=>{
        const card=document.getElementById(inst.card);
        if(card){card.classList.remove('is-complete','is-failed');card.classList.add('is-active');}
        const fillEl=document.getElementById(inst.fill);if(fillEl)fillEl.style.width='0%';
        const pctEl=document.getElementById(inst.pct);if(pctEl)pctEl.textContent='0%';
        const labelEl=document.getElementById(inst.label);if(labelEl)labelEl.textContent='Initializing...';
        const elapsedEl=document.getElementById(inst.elapsed);if(elapsedEl)elapsedEl.textContent='Elapsed: 0:00';
        const phaseWrapEl=document.getElementById(inst.phaseWrap);
        if(phaseWrapEl)phaseWrapEl.innerHTML=`<i class="fas fa-spinner"></i> <span id="${inst.phaseText}">Scanning . . .</span>`;
        wrapEl.hidden=false;
    });
    resetScanStepper();
    const grid=document.getElementById('scanResultGrid');if(grid)grid.innerHTML='';
}
let activeScanJobId=localStorage.getItem('oxsActiveScanJob');
let activeScanStart=localStorage.getItem('oxsActiveScanStart');
let scanPollInterval=null;
function persistScanJob(j,target,mode){localStorage.setItem('oxsActiveScanJob',j);localStorage.setItem('oxsActiveScanStart',Date.now().toString());localStorage.setItem('oxsActiveScanTarget',target||'');localStorage.setItem('oxsActiveScanMode',mode||'basic');activeScanJobId=j;activeScanStart=Date.now().toString();}
function clearPersistedScan(){localStorage.removeItem('oxsActiveScanJob');localStorage.removeItem('oxsActiveScanStart');localStorage.removeItem('oxsActiveScanTarget');localStorage.removeItem('oxsActiveScanMode');activeScanJobId=null;activeScanStart=null;}
function formatElapsed(ms){const s=Math.floor(ms/1000);return `${Math.floor(s/60)}:${(s%60).toString().padStart(2,'0')}`;}

document.getElementById('quickScanBtn').addEventListener('click',async function(){
    const t=document.getElementById('quickScanTarget').value.trim();
    if(!t)return showToast('Enter a target domain','error');
    const b=this;b.disabled=true;const o=b.innerHTML;
    b.innerHTML='<i class="fas fa-spinner spin"></i>Scanning...';
    try{
        const r=await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:t,mode:'basic',tools:[]})});
        const d=await r.json();
        if(d.error){showToast(d.error,'error');b.disabled=false;b.innerHTML=o;return;}
        document.getElementById('quickScanTarget').value='';
        persistScanJob(d.job_id,t,'basic');resetProgressUI();pollScan(d.job_id,t,true,'basic');
    }catch(e){showToast('Scan request failed','error');b.disabled=false;b.innerHTML=o;}
});

document.getElementById('scanBtn').addEventListener('click',async function(){
    const t=document.getElementById('scanTarget').value.trim();
    const m=document.getElementById('scanMode').value;
    const sel=Array.from(document.querySelectorAll('#toolChecklist input:checked')).map(i=>i.value);
    if(!t)return showToast('Enter target','error');
    if(!sel.length)return showToast('Select at least one tool','error');
    const b=this;b.disabled=true;resetProgressUI();
    try{
        const r=await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:t,mode:m,tools:sel})});
        const d=await r.json();
        if(d.error){showToast(d.error,'error');b.disabled=false;return;}
        persistScanJob(d.job_id,t,m);pollScan(d.job_id,t,false,m);
    }catch(e){showToast('Scan request failed','error');b.disabled=false;}
});

function pollScan(jobId,target,isQuick,modeUsed){
    if(scanPollInterval)clearInterval(scanPollInterval);
    const start=activeScanStart?parseInt(activeScanStart):Date.now();
    const updateTimer=()=>{
        const txt=`Elapsed: ${formatElapsed(Date.now()-start)}`;
        forEachScanUi(inst=>{const el=document.getElementById(inst.elapsed);if(el)el.textContent=txt;});
    };
    updateTimer();
    scanPollInterval=setInterval(async()=>{
        try{
            const r=await fetch(`/api/scan/${jobId}/status`);
            if(!r.ok){clearInterval(scanPollInterval);return;}
            const job=await r.json();
            const pct=job.percent||0;
            forEachScanUi(inst=>{
                const fillEl=document.getElementById(inst.fill);if(fillEl)fillEl.style.width=pct+'%';
                const pctEl=document.getElementById(inst.pct);if(pctEl)pctEl.textContent=pct+'%';
                const labelEl=document.getElementById(inst.label);if(labelEl)labelEl.textContent=job.current_tool||'Processing';
            });
            updateScanPhase(pct);updateTimer();
            updateScanPopupProgress(pct,job.current_tool);
            if(job.status==='completed'){
                clearInterval(scanPollInterval);
                forEachScanUi(inst=>{
                    const card=document.getElementById(inst.card);
                    if(card){card.classList.remove('is-active','is-failed');card.classList.add('is-complete');}
                    const fillEl=document.getElementById(inst.fill);if(fillEl)fillEl.style.width='100%';
                    const pctEl=document.getElementById(inst.pct);if(pctEl)pctEl.textContent='100%';
                    const labelEl=document.getElementById(inst.label);if(labelEl)labelEl.textContent=`Scan complete — ${target}`;
                    const phaseWrapEl=document.getElementById(inst.phaseWrap);
                    if(phaseWrapEl)phaseWrapEl.innerHTML=`<i class="fas fa-check-circle" style="color:var(--green);"></i> <span style="color:var(--green);">Scan completed successfully</span>`;
                });
                updateScanStepper(100);
                renderResults(job.results);
                document.getElementById('scanBtn').disabled=false;
                document.getElementById('quickScanBtn').disabled=false;
                document.getElementById('quickScanBtn').innerHTML='<i class="fas fa-play"></i> Run Quick Scan';
                if(getStoragePref()==='local'){
                    addLocalHistoryEntry({id:Date.now(),target,mode:modeUsed||'basic',status:'completed',created_at:new Date().toISOString(),result:job.results});
                }
                refreshOverview();showToast(`Scan completed for ${target}`);clearPersistedScan();
                finishScanPopup(true,target);
            }
            if(job.status==='failed'){
                clearInterval(scanPollInterval);
                forEachScanUi(inst=>{
                    const card=document.getElementById(inst.card);
                    if(card){card.classList.remove('is-active','is-complete');card.classList.add('is-failed');}
                    const labelEl=document.getElementById(inst.label);if(labelEl)labelEl.textContent=`Failed — ${job.error||'unknown error'}`;
                    const phaseWrapEl=document.getElementById(inst.phaseWrap);
                    if(phaseWrapEl)phaseWrapEl.innerHTML=`<i class="fas fa-times-circle" style="color:var(--red-500);"></i> <span style="color:var(--red-500);">Scan failed</span>`;
                });
                document.getElementById('scanBtn').disabled=false;
                document.getElementById('quickScanBtn').disabled=false;
                document.getElementById('quickScanBtn').innerHTML='<i class="fas fa-play"></i> Run Quick Scan';
                showToast(`Scan failed: ${job.error||'unknown'}`,'error');clearPersistedScan();
                finishScanPopup(false,target,job.error);
            }
        }catch(e){clearInterval(scanPollInterval);}
    },800);
}

// ─── RESULT RENDERERS ──────────────────────────────────────
function renderResultsSummaryBar(results){
    const toolCount=Object.keys(results).length;
    let totalTime=0, haveTime=false, vulnCount=0;
    Object.values(results).forEach(r=>{
        const d=r.data||r;
        if(typeof d.scan_time==='number'){ totalTime+=d.scan_time; haveTime=true; }
        if((d.scan_type==='xss'||d.scan_type==='sqli')&&d.vulnerable&&Array.isArray(d.findings)){ vulnCount+=d.findings.length; }
    });
    return `<div class="result-summary-bar">
        <div class="rsb-item"><i class="fas fa-layer-group"></i><div><span class="rsb-label">Modules Run</span><strong>${toolCount}</strong></div></div>
        ${haveTime?`<div class="rsb-item"><i class="fas fa-stopwatch"></i><div><span class="rsb-label">Total Time</span><strong>${totalTime.toFixed(2)}s</strong></div></div>`:''}
        <div class="rsb-item"><i class="fas fa-bug" style="${vulnCount?'color:var(--red-500);':''}"></i><div><span class="rsb-label">Vulnerabilities</span><strong style="${vulnCount?'color:var(--red-500);':''}">${vulnCount}</strong></div></div>
        <div class="rsb-item rsb-status"><i class="fas fa-circle-check"></i><div><span class="rsb-label">Status</span><strong data-i18n="rsb_complete">Complete</strong></div></div>
    </div>`;
}
function renderScannerFinding(f){
    const pattern = f.pattern || f.type || f.rule || f.name || 'Match';
    const confidence = String(f.confidence || f.level || '--');
    const value = f.match || f.value || f.secret || f.snippet || '';
    const location = f.location || f.url || f.source || f.file || f.path || '';
    const line = f.line ?? f.line_number ?? null;
    const confColorMap = {high:'var(--red-500)', medium:'var(--amber)', low:'var(--steel)', entropy:'var(--gold)'};
    const confColor = confColorMap[confidence.toLowerCase()] || 'var(--text-muted)';
    return `<div class="scn-finding">
        <div class="scn-finding-head">
            <span class="scn-finding-pattern">${escapeHtml(pattern)}</span>
            <span class="scn-finding-confidence" style="color:${confColor};">${escapeHtml(confidence)}</span>
        </div>
        ${value?`<code class="scn-finding-value">${escapeHtml(String(value))}</code>`:''}
        ${location?`<div class="scn-finding-loc"><i class="fas fa-location-dot"></i> ${escapeHtml(String(location))}${line!==null?` : line ${line}`:''}</div>`:''}
    </div>`;
}
function renderScannerResult(toolResult){
    const d=toolResult.data||toolResult;
    const findings=d.findings||[];
    const stats=d.stats||{};
    const conf=stats.by_confidence||{};
    const byPattern=stats.by_pattern||{};
    const total=stats.total??findings.length;
    const patternEntries=Object.entries(byPattern);
    const listId='scnFindings_'+Math.random().toString(36).slice(2,9);
    const chip=(label,key,color)=>`<div class="scn-stat"><span class="scn-stat-value" style="color:${color};">${conf[key]??0}</span><span class="scn-stat-label">${label}</span></div>`;
    return `<div class="result-card scanner-card">
        <div class="result-card-header">
            <strong>${escapeHtml(toolResult.tool||'Secret & Exposure Scanner')}</strong>
            ${total>0?`<span class="badge" style="color:var(--red-500);"><i class="fas fa-triangle-exclamation"></i> ${total} Finding${total===1?'':'s'}</span>`:`<span class="badge success"><i class="fas fa-shield-check"></i> Clean</span>`}
        </div>
        <div class="scn-target"><i class="fas fa-crosshairs"></i> ${escapeHtml(d.scanned||'--')}</div>
        <div class="scn-stats-row">
            ${chip('High','high','var(--red-500)')}
            ${chip('Medium','medium','var(--amber)')}
            ${chip('Low','low','var(--steel)')}
            ${chip('Entropy','entropy','var(--gold)')}
        </div>
        ${patternEntries.length?`<div class="scn-pattern-chips">${patternEntries.map(([k,v])=>`<span class="scn-pattern-chip">${escapeHtml(k)} <b>${v}</b></span>`).join('')}</div>`:''}
        ${findings.length?`
            <button class="btn-secondary scn-toggle-btn" data-target="${listId}"><i class="fas fa-list"></i> <span>View All ${findings.length} Finding${findings.length===1?'':'s'}</span></button>
            <div class="scn-findings-list" id="${listId}" hidden>${findings.map(renderScannerFinding).join('')}</div>
        `:`<div class="scn-empty"><i class="fas fa-shield-check"></i> No exposed secrets or sensitive patterns detected.</div>`}
    </div>`;
}
// Event delegation — findings lists are inserted dynamically, so the
// toggle button is wired once here instead of per-render.
document.getElementById('scanResultGrid')?.addEventListener('click',(e)=>{
    const btn=e.target.closest('.scn-toggle-btn');
    if(!btn)return;
    const list=document.getElementById(btn.dataset.target);
    if(!list)return;
    const willShow=list.hidden;
    list.hidden=!willShow;
    btn.classList.toggle('is-open', willShow);
    btn.querySelector('i').className = willShow ? 'fas fa-chevron-up' : 'fas fa-list';
});
function renderResults(results){
    const grid=document.getElementById('scanResultGrid');
    if(!results||!Object.keys(results).length){grid.innerHTML='<div class="empty-state">No results returned.</div>';return;}
    let html='';
    for(const[toolKey,rawResult]of Object.entries(results)){
        try{
            const toolResult=(rawResult&&typeof rawResult==='object')?rawResult:{tool:toolKey,data:{error:'module_error',message:rawResult==null?'No data was returned for this module.':String(rawResult)}};
            const data=toolResult.data||toolResult||{};
            if(toolKey==='whois'||toolKey==='whois_lookup')html+=renderWhoisResult(toolResult);
            else if(toolKey==='xss'||data.scan_type==='xss')html+=renderXssResult(toolResult);
            else if(toolKey==='sql_map'||toolKey==='sqli'||toolKey==='sql_injection'||data.scan_type==='sqli')html+=renderSqliResult(toolResult);
            else if(data.open_ports_details&&Array.isArray(data.open_ports_details))html+=renderPortScanResult(toolResult);
            else if(data.score_percent!==undefined||data.missing_headers!==undefined||data.all_response_headers!==undefined)html+=renderHeadersResult(toolResult);
            else if(data.attempts!==undefined&&data.avg_ms!==undefined)html+=renderConnectivityResult(toolResult);
            else if(data.A!==undefined||data.MX!==undefined||data.NS!==undefined)html+=renderDnsResult(toolResult);
            else if(data.spf!==undefined||data.dmarc!==undefined||data.dkim_selectors_found!==undefined)html+=renderEmailSecurityResult(toolResult);
            // SSL checked early — matches by tool key AND by unique field combo so a
// future module that happens to add an `ip` field can't shadow it.
else if(toolKey==='ssl_check'||toolKey==='ssl'||data.protocol_weak!==undefined||data.cipher_suite!==undefined)html+=renderSslResult(toolResult);
else if(data.ip&&data.isp&&data.country)html+=renderIpInfoResult(toolResult);
            else if(data.subdomains&&Array.isArray(data.subdomains))html+=renderSubdomainResult(toolResult);
            else if(toolKey==='tech_fingerprint'||toolKey==='tech'||data.detected!==undefined||data.summary_by_category!==undefined)html+=renderTechFingerprintResult(toolResult);
            else if(data.findings!==undefined&&data.stats!==undefined)html+=renderScannerResult(toolResult);
            else if(data.error==='module_not_found')html+=`<div class="result-card"><div class="result-card-header"><strong>${escapeHtml(toolResult.tool||toolKey)}</strong><span class="badge"><i class="fas fa-plug-circle-xmark"></i> Not Installed</span></div><p style="color:var(--text-muted);font-size:0.8rem;">${escapeHtml(data.message||'This module is not installed on the server yet.')}</p></div>`;
            else if(data.error==='module_error')html+=`<div class="result-card"><div class="result-card-header"><strong>${escapeHtml(toolResult.tool||toolKey)}</strong><span class="badge" style="color:var(--red-500);"><i class="fas fa-triangle-exclamation"></i> Error</span></div><p style="color:var(--text-muted);font-size:0.8rem;">${escapeHtml(data.message||'This module raised an error.')}</p></div>`;
            else html+=`<div class="result-card"><div class="result-card-header"><strong>${escapeHtml(toolResult.tool||toolKey)}</strong><span class="badge success"><i class="fas fa-check"></i> OK</span></div><pre>${escapeHtml(JSON.stringify(data,null,2))}</pre></div>`;
        }catch(err){
            let raw; try{ raw=JSON.stringify(rawResult,null,2); }catch(e2){ raw=String(rawResult); }
            html+=`<div class="result-card"><div class="result-card-header"><strong>${escapeHtml(toolKey)}</strong><span class="badge" style="color:var(--red-500);"><i class="fas fa-triangle-exclamation"></i> Display Error</span></div><p style="color:var(--text-muted);font-size:0.8rem;">This module returned data the console could not render. Raw output is preserved below.</p><pre>${escapeHtml(raw)}</pre></div>`;
        }
    }
    grid.innerHTML=renderResultsSummaryBar(results)+html;
}

function renderWhoisResult(toolResult){
    const d=toolResult.data||toolResult;
    // Not-found / error state
    if(d.found===false){
        return `<div class="result-card vuln-card"><div class="result-card-header"><strong><i class="fas fa-id-card vuln-ico"></i> WHOIS Lookup</strong><span class="badge warning"><i class="fas fa-circle-question"></i> No Record</span></div><div class="vuln-clean" style="color:var(--text-muted);"><i class="fas fa-circle-info"></i> ${escapeHtml(toolResult.error||'No WHOIS record found for this domain.')}</div></div>`;
    }
    const asList=(v)=>Array.isArray(v)?v:(v!=null&&v!==''?[String(v)]:[]);
    const daysExp=d.days_until_expiry, ageDays=d.domain_age_days;
    let expColor='var(--green)', expText=(daysExp!=null?`${daysExp}d`:'--');
    if(d.is_expired){expColor='var(--red-500)';expText='Expired';}
    else if(d.expiring_soon){expColor='var(--amber)';}
    const ageText = ageDays!=null ? (ageDays>=365?`${(ageDays/365).toFixed(1)}y`:`${ageDays}d`) : '--';
    const chips=(arr,cls)=>arr.map(v=>`<span class="record-chip"><span class="rc-value">${escapeHtml(String(v))}</span></span>`).join('');
    let statusBadge=`<span class="badge success"><i class="fas fa-check"></i> Resolved</span>`;
    if(d.is_expired)statusBadge=`<span class="badge danger"><i class="fas fa-triangle-exclamation"></i> Expired</span>`;
    else if(d.expiring_soon)statusBadge=`<span class="badge warning"><i class="fas fa-hourglass-half"></i> Expiring Soon</span>`;
    let html=`<div class="result-card"><div class="result-card-header"><strong><i class="fas fa-id-card vuln-ico" style="color:var(--steel);"></i> WHOIS Lookup</strong>${statusBadge}</div>
        <div class="vuln-target"><i class="fas fa-globe"></i> ${escapeHtml(String(d.queried_domain||d.domain_name||toolResult.target||'--'))}</div>
        <div class="port-summary-grid">
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--gold);font-size:0.98rem;">${escapeHtml(String(d.registrar||'--')).slice(0,22)}</div><div class="port-summary-label">Registrar</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:${expColor};">${expText}</div><div class="port-summary-label">Expires In</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--steel);">${ageText}</div><div class="port-summary-label">Domain Age</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--amber);font-size:0.82rem;">${escapeHtml(String(d.updated_date||'--')).slice(0,10)}</div><div class="port-summary-label">Last Updated</div></div>
        </div>
        <table class="data-table" style="margin-top:6px;"><tbody>
            <tr><td style="font-weight:600;width:32%;">Domain</td><td>${escapeHtml(String(d.domain_name||'--'))}</td></tr>
            <tr><td style="font-weight:600;">Created</td><td>${escapeHtml(String(d.creation_date||'--'))}</td></tr>
            <tr><td style="font-weight:600;">Expires</td><td>${escapeHtml(String(d.expiration_date||'--'))}</td></tr>`;
    if(d.whois_server)html+=`<tr><td style="font-weight:600;">WHOIS Server</td><td style="font-family:var(--font-mono);font-size:0.72rem;">${escapeHtml(String(d.whois_server))}</td></tr>`;
    if(d.dnssec)html+=`<tr><td style="font-weight:600;">DNSSEC</td><td>${escapeHtml(String(d.dnssec))}</td></tr>`;
    if(d.org)html+=`<tr><td style="font-weight:600;">Organisation</td><td>${escapeHtml(String(d.org))}</td></tr>`;
    if(d.country||d.state||d.city){const loc=[d.city,d.state,d.country].filter(Boolean).map(String).join(', ');html+=`<tr><td style="font-weight:600;">Location</td><td>${escapeHtml(loc)}</td></tr>`;}
    html+=`</tbody></table>`;
    const ns=asList(d.name_servers);
    if(ns.length)html+=`<div style="margin-top:10px;"><strong style="font-size:0.72rem;color:var(--steel);text-transform:uppercase;letter-spacing:0.5px;">Name Servers (${ns.length})</strong><div style="margin-top:5px;">${chips(ns)}</div></div>`;
    const st=asList(d.status);
    if(st.length)html+=`<div style="margin-top:10px;"><strong style="font-size:0.72rem;color:var(--steel);text-transform:uppercase;letter-spacing:0.5px;">Status (${st.length})</strong><div style="margin-top:5px;">${st.map(s=>`<span class="badge info" style="margin:2px;">${escapeHtml(String(s).split(' ')[0])}</span>`).join('')}</div></div>`;
    const em=asList(d.emails);
    if(em.length)html+=`<div style="margin-top:10px;"><strong style="font-size:0.72rem;color:var(--steel);text-transform:uppercase;letter-spacing:0.5px;">Contact Emails</strong><div style="margin-top:5px;font-family:var(--font-mono);font-size:0.72rem;color:var(--text-secondary);">${em.map(e=>escapeHtml(String(e))).join('<br>')}</div></div>`;
    return html+`</div>`;
}

function renderXssResult(toolResult){
    const d=toolResult.data||toolResult;
    const findings=d.findings||[];
    const vulnerable=!!d.vulnerable;
    const url=d.url||toolResult.target||'--';
    const params=d.parameters_tested||[];
    const payloads=d.payloads_tested||0;
    const mode=d.mode||'basic';
    const err=toolResult.error;
    const badge=vulnerable?`<span class="badge danger"><i class="fas fa-triangle-exclamation"></i> Vulnerable</span>`:`<span class="badge success"><i class="fas fa-shield-halved"></i> No XSS</span>`;
    let html=`<div class="result-card vuln-card ${vulnerable?'is-vuln':'is-clean'}">
        <div class="result-card-header"><strong><i class="fas fa-bolt vuln-ico"></i> XSS Scanner</strong>${badge}</div>
        <div class="vuln-target"><i class="fas fa-link"></i> ${escapeHtml(String(url))}</div>
        <div class="port-summary-grid">
            <div class="port-summary-card"><div class="port-summary-value" style="color:${vulnerable?'var(--red-500)':'var(--green)'};">${findings.length}</div><div class="port-summary-label">Findings</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--steel);">${payloads}</div><div class="port-summary-label">Payloads</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--gold);">${params.length}</div><div class="port-summary-label">Params</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--amber);text-transform:capitalize;">${escapeHtml(mode)}</div><div class="port-summary-label">Mode</div></div>
        </div>`;
    if(err)html+=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ${escapeHtml(String(err))}</div>`;
    if(findings.length){
        html+=`<div class="vuln-alert"><i class="fas fa-triangle-exclamation"></i> Reflected XSS confirmed — sanitise or encode the affected parameter(s).</div><div class="port-table-wrap"><table class="data-table"><thead><tr><th>Parameter</th><th>Payload</th><th>Status</th></tr></thead><tbody>${findings.map(f=>`<tr><td style="font-family:var(--font-mono);color:var(--red-400);font-weight:600;">${escapeHtml(String(f.parameter||'--'))}</td><td><code class="vuln-payload">${escapeHtml(String(f.payload||'').slice(0,120))}</code></td><td style="font-family:var(--font-mono);">${escapeHtml(String(f.status_code||'--'))}</td></tr>`).join('')}</tbody></table></div>`;
    }else if(!err){
        html+=`<div class="vuln-clean"><i class="fas fa-shield-check"></i> No reflected XSS detected across ${params.length||'the'} parameter(s).</div>`;
    }
    return html+`</div>`;
}

function renderSqliResult(toolResult){
    const d=toolResult.data||toolResult;
    const findings=d.findings||[];
    const vulnerable=!!d.vulnerable;
    const url=d.url||toolResult.target||'--';
    const techniques=d.techniques_tested||[];
    const requests=d.requests_sent||0;
    const duration=d.duration!=null?d.duration:null;
    const dbHint=d.database_hint||null;
    const err=toolResult.error;
    const badge=vulnerable?`<span class="badge danger"><i class="fas fa-triangle-exclamation"></i> Injectable</span>`:`<span class="badge success"><i class="fas fa-shield-halved"></i> No SQLi</span>`;
    const statusColors={confirmed:'var(--red-500)',probable:'var(--amber)',possible:'var(--steel)',inconclusive:'var(--text-muted)',blocked:'var(--gold)'};
    const statusPill=(s)=>{const k=String(s||'').toLowerCase();return `<span class="vuln-status" style="color:${statusColors[k]||'var(--text-muted)'};border-color:${statusColors[k]||'var(--border-color)'};">${escapeHtml(String(s||'--'))}</span>`;};
    let html=`<div class="result-card vuln-card ${vulnerable?'is-vuln':'is-clean'}">
        <div class="result-card-header"><strong><i class="fas fa-database vuln-ico"></i> SQLMap — SQL Injection</strong>${badge}</div>
        <div class="vuln-target"><i class="fas fa-link"></i> ${escapeHtml(String(url))}</div>
        <div class="port-summary-grid">
            <div class="port-summary-card"><div class="port-summary-value" style="color:${vulnerable?'var(--red-500)':'var(--green)'};">${findings.length}</div><div class="port-summary-label">Findings</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--steel);">${requests}</div><div class="port-summary-label">Requests</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--gold);">${duration!=null?duration+'s':'--'}</div><div class="port-summary-label">Duration</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--amber);">${dbHint?escapeHtml(String(dbHint)):'--'}</div><div class="port-summary-label">DB Engine</div></div>
        </div>
        ${techniques.length?`<div class="vuln-tech-row">${techniques.map(t=>`<span class="badge info"><i class="fas fa-vial"></i> ${escapeHtml(String(t))}</span>`).join(' ')}</div>`:''}`;
    if(err)html+=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ${escapeHtml(String(err))}</div>`;
    if(findings.length){
        html+=`<div class="vuln-alert"><i class="fas fa-triangle-exclamation"></i> Potential SQL injection — verify each finding against its confidence &amp; status before reporting.</div><div class="port-table-wrap"><table class="data-table"><thead><tr><th>Parameter</th><th>Technique</th><th>Confidence</th><th>Status</th><th>DB</th></tr></thead><tbody>${findings.map(f=>{const conf=f.confidence!=null?Math.round(Number(f.confidence)*100)+'%':'--';return `<tr><td style="font-family:var(--font-mono);color:var(--red-400);font-weight:600;">${escapeHtml(String(f.parameter||'--'))}</td><td><span class="badge">${escapeHtml(String(f.technique||'--'))}</span></td><td style="font-family:var(--font-mono);">${conf}</td><td>${statusPill(f.status)}</td><td>${escapeHtml(String(f.database_type||'--'))}</td></tr>`;}).join('')}</tbody></table></div>`;
    }else if(!err){
        html+=`<div class="vuln-clean"><i class="fas fa-shield-check"></i> No SQL injection detected with the selected techniques.</div>`;
    }
    return html+`</div>`;
}

function renderPortScanResult(toolResult){
    const data=toolResult.data||toolResult;
    const openPorts=data.open_ports_details;const totalScanned=data.ports_checked||0;
    const openCount=data.open_count||openPorts.length;const closedCount=totalScanned-openCount;
    return `<div class="result-card"><div class="result-card-header"><strong>Port Scan</strong><span class="badge success"><i class="fas fa-check"></i> Scan Complete</span></div>
        <div class="port-summary-grid">
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--steel);">${totalScanned}</div><div class="port-summary-label">Ports Scanned</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--green);">${openCount}</div><div class="port-summary-label">Open</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--amber);">${closedCount}</div><div class="port-summary-label">Closed / Filtered</div></div>
            <div class="port-summary-card"><div class="port-summary-value" style="color:var(--gold);">${data.scan_time}s</div><div class="port-summary-label">Scan Duration</div></div>
        </div>
        <div style="margin:8px 0;font-size:0.72rem;color:var(--text-muted);">Resolved IP: <span style="color:var(--text-primary);">${escapeHtml(String(data.resolved_ip||'unknown'))}</span> &middot; Threads: ${data.threads_used||'--'}</div>
        ${openPorts.length?`<div class="port-table-wrap"><table class="data-table"><thead><tr><th>Port</th><th>Service</th><th>Response (ms)</th></tr></thead><tbody>${openPorts.map(p=>`<tr><td style="font-family:var(--font-mono);color:var(--text-primary);">${escapeHtml(String(p.port))}/tcp</td><td><span class="badge">${escapeHtml(String(p.service||'unknown'))}</span></td><td style="font-family:var(--font-mono);">${(p.response_time*1000).toFixed(1)} ms</td></tr>`).join('')}</tbody></table></div>`:`<div class="empty-state" style="margin-top:12px;">No open ports detected — all ${totalScanned} ports are closed or filtered.</div>`}</div>`;
}

function renderHeadersResult(toolResult){
    const d=toolResult.data||toolResult;const score=d.score_percent||0;
    const severity=d.highest_severity||'unknown';const server=d.server||d.all_response_headers?.Server||'unknown';
    const statusCode=d.status_code||'--';const redirects=d.redirect_count||0;
    const presentCount=Object.keys(d.present_headers||{}).length;
    const missingHeaders=d.missing_headers||[];const presentHeaders=d.present_headers||{};
    const cookies=d.cookies||[];const cspAnalysis=d.csp_analysis||{};
    const allHeaders=d.all_response_headers||{};const finalUrl=d.final_url||d.url||'';
    let scoreColor='var(--red-500)',scoreGlow='var(--red-glow)';
    if(score>=70){scoreColor='var(--green)';scoreGlow='var(--green-glow)';}
    else if(score>=40){scoreColor='var(--amber)';scoreGlow='var(--amber-glow)';}
    const circumference=2*Math.PI*38;const dashOffset=circumference-(score/100)*circumference;
    let html=`<div class="result-card" style="border-left:3px solid ${scoreColor};"><div class="result-card-header"><strong>HTTP Security Headers</strong><span class="badge ${severity==='critical'?'danger':severity==='hard'?'warning':'info'}"><i class="fas fa-shield-halved"></i> ${severity.toUpperCase()}</span></div>
        <div class="score-circle-wrap"><div class="score-circle" style="animation:scorePulse 2s ease-in-out 1;"><svg viewBox="0 0 90 90"><circle class="bg-circle" cx="45" cy="45" r="38"/><circle class="fg-circle" cx="45" cy="45" r="38" stroke="${scoreColor}" stroke-dasharray="${circumference}" stroke-dashoffset="${dashOffset}" style="filter:drop-shadow(0 0 6px ${scoreGlow});"/></svg><div class="score-text" style="color:${scoreColor};">${score}%</div><div class="score-label">Security Score</div></div>
        <div class="port-summary-grid" style="flex:1;margin-bottom:0;"><div class="port-summary-card"><div class="port-summary-value" style="color:var(--steel);">${statusCode}</div><div class="port-summary-label">Status Code</div></div><div class="port-summary-card"><div class="port-summary-value" style="color:var(--gold);">${server}</div><div class="port-summary-label">Server</div></div><div class="port-summary-card"><div class="port-summary-value" style="color:var(--amber);">${redirects}</div><div class="port-summary-label">Redirects</div></div><div class="port-summary-card"><div class="port-summary-value" style="color:var(--green);">${presentCount}</div><div class="port-summary-label">Headers Found</div></div></div></div>`;
    if(finalUrl)html+=`<div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:10px;">URL: <span style="color:var(--text-primary);">${finalUrl}</span></div>`;
    if(Object.keys(presentHeaders).length){
        html+=`<div style="margin-bottom:10px;"><strong style="font-size:0.78rem;color:var(--text-primary);">Present Security Headers</strong></div><table class="data-table" style="margin-bottom:12px;"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>`;
        for(const[h,v]of Object.entries(presentHeaders))html+=`<tr><td style="color:var(--green);font-weight:600;">${h}</td><td style="font-family:var(--font-mono);font-size:0.7rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(String(v))}">${escapeHtml(String(v).substring(0,80))}${String(v).length>80?'...':''}</td></tr>`;
        html+=`</tbody></table>`;
    }
    if(missingHeaders.length){
        html+=`<div style="margin-bottom:8px;"><strong style="font-size:0.78rem;color:var(--text-primary);">Missing Security Headers (${missingHeaders.length})</strong></div>`;
        for(const m of missingHeaders){
            const sev=m.severity||'normal';
            html+=`<div class="severity-card ${sev}"><span class="severity-dot ${sev}"></span><div style="flex:1;"><div style="font-weight:600;font-size:0.78rem;color:var(--text-primary);">${m.header}</div><div style="font-size:0.7rem;color:var(--text-secondary);">${m.description||''}</div></div><span class="badge ${sev==='critical'?'danger':sev==='hard'?'warning':'info'}">${sev}</span></div>`;
        }
    }
    if(cookies.length){
        html+=`<div style="margin:12px 0 8px;"><strong style="font-size:0.78rem;color:var(--text-primary);">Cookies (${cookies.length})</strong></div>`;
        for(const ck of cookies){
            const nv=ck.name_value||'';const secure=ck.secure;const httponly=ck.httponly;const samesite=ck.samesite||'none';
            html+=`<div class="cookie-row"><code>${escapeHtml(nv)}</code><div class="cookie-flags"><span class="cookie-flag ${secure?'on':'off'}">Secure</span><span class="cookie-flag ${httponly?'on':'off'}">HttpOnly</span><span class="cookie-flag ${samesite!=='none'?'on':'off'}">SameSite:${samesite}</span></div></div>`;
        }
    }
    if(Object.keys(cspAnalysis).length){
        html+=`<div class="accordion-item" style="margin-top:12px;"><div class="accordion-header" onclick="this.parentElement.classList.toggle('open')"><span><i class="fas fa-lock"></i> CSP Policy Analysis</span><i class="fas fa-chevron-down chevron"></i></div><div class="accordion-body" style="max-height:300px;overflow-y:auto;">`;
        for(const[directive,sources]of Object.entries(cspAnalysis)){
            html+=`<div style="margin-bottom:8px;"><strong style="color:var(--text-primary);">${directive}</strong>`;
            if(Array.isArray(sources))html+=`<div style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-secondary);margin-top:3px;">${sources.map(s=>`<span style="background:var(--bg-tertiary);padding:1px 5px;border-radius:3px;margin-right:4px;display:inline-block;">${escapeHtml(s)}</span>`).join(' ')}</div>`;
            html+=`</div>`;
        }
        html+=`</div></div>`;
    }
    html+=`<div class="accordion-item" style="margin-top:8px;"><div class="accordion-header" onclick="this.parentElement.classList.toggle('open')"><span><i class="fas fa-list"></i> All Response Headers (${Object.keys(allHeaders).length})</span><i class="fas fa-chevron-down chevron"></i></div><div class="accordion-body"><table class="data-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>`;
    for(const[h,v]of Object.entries(allHeaders))html+=`<tr><td style="font-weight:600;">${h}</td><td style="font-family:var(--font-mono);font-size:0.68rem;word-break:break-all;">${escapeHtml(String(v).substring(0,150))}${String(v).length>150?'...':''}</td></tr>`;
    html+=`</tbody></table></div></div></div>`;
    return html;
}

function renderConnectivityResult(toolResult){
    const d=toolResult.data||toolResult;const ip=d.resolved_ip||'unknown';
    const attempts=d.attempts||0;const success=d.successful||0;
    const avg=d.avg_ms||0;const min=d.min_ms||0;const max=d.max_ms||0;
    const loss=d.packet_loss_percent||0;const pct=attempts?Math.round((success/attempts)*100):0;
    let lc='var(--green)';if(pct<80)lc='var(--amber)';if(pct<50)lc='var(--red-500)';
    return `<div class="result-card"><div class="result-card-header"><strong>Connectivity Check</strong><span class="badge ${pct===100?'success':pct>=80?'warning':'danger'}"><i class="fas fa-${pct===100?'check':'exclamation-triangle'}"></i> ${pct}% Success</span></div><div class="port-summary-grid"><div class="port-summary-card"><div class="port-summary-value" style="color:var(--steel);">${success}/${attempts}</div><div class="port-summary-label">Packets</div></div><div class="port-summary-card"><div class="port-summary-value" style="color:${lc};">${avg.toFixed(1)} ms</div><div class="port-summary-label">Avg Latency</div></div><div class="port-summary-card"><div class="port-summary-value" style="color:var(--green);">${min.toFixed(1)} ms</div><div class="port-summary-label">Min</div></div><div class="port-summary-card"><div class="port-summary-value" style="color:var(--amber);">${max.toFixed(1)} ms</div><div class="port-summary-label">Max</div></div></div><div style="margin-bottom:8px;font-size:0.72rem;color:var(--text-muted);">Resolved IP: <span style="color:var(--text-primary);">${ip}</span> &middot; Packet Loss: <span style="color:${loss>0?'var(--red-500)':'var(--green)'};">${loss}%</span></div><div class="latency-bar"><div class="latency-bar-fill" style="width:${Math.min(100,(avg/200)*100)}%;background:linear-gradient(90deg,var(--green),var(--amber),var(--red-500));"></div></div></div>`;
}

function renderDnsResult(toolResult){
    const d=toolResult.data||toolResult;
    let h=`<div class="result-card"><div class="result-card-header"><strong>DNS Records</strong><span class="badge success"><i class="fas fa-check"></i> Resolved</span></div>`;
    const types=[['A','IPv4 Address'],['AAAA','IPv6 Address'],['MX','Mail Exchange'],['NS','Name Servers'],['CNAME','Canonical Name'],['SOA','Start of Authority'],['TXT','Text Records']];
    for(const[key,label]of types){
        const vals=d[key];
        if(vals&&Array.isArray(vals)&&vals.length){
            h+=`<div style="margin-bottom:10px;"><strong style="font-size:0.72rem;color:var(--steel);text-transform:uppercase;letter-spacing:0.5px;">${label} (${vals.length})</strong><div style="margin-top:4px;">`;
            vals.forEach(v=>{h+=`<span class="record-chip"><span class="rc-type">${key}</span><span class="rc-value">${escapeHtml(String(v))}</span></span>`;});
            h+=`</div></div>`;
        }
    }
    return h+`</div>`;
}

function parseSpfRecord(raw){
    const record=String(raw||'').trim();
    if(!record) return null;
    const tokens=record.split(/\s+/).filter(Boolean);
    const mechanisms=[]; let allQualifier=null;
    tokens.forEach(tok=>{
        if(/^v=spf1$/i.test(tok)) return;
        const allMatch=tok.match(/^([+\-~?]?)all$/i);
        if(allMatch){ allQualifier=(allMatch[1]||'+')+'all'; return; }
        if(/^[+\-~?]?(include|ip4|ip6|a|mx|ptr|exists|redirect)(:|=|$)/i.test(tok)) mechanisms.push(tok);
    });
    const qualifiers={
        '-all':{ label:'Hard Fail (-all)', tone:'pass', note:'Unauthorized senders are rejected outright — the strictest and recommended setting.' },
        '~all':{ label:'Soft Fail (~all)', tone:'warn', note:'Unauthorized senders are flagged but typically still delivered — reasonable during rollout, not as an end state.' },
        '?all':{ label:'Neutral (?all)', tone:'warn', note:'No policy is asserted for unlisted senders — this offers no real protection.' },
        '+all':{ label:'Pass All (+all)', tone:'fail', note:'Any server is permitted to send as this domain — this misconfiguration defeats SPF entirely.' }
    };
    const lookupCount=mechanisms.filter(m=>/^[+\-~?]?(include|a|mx|ptr|exists|redirect)(:|=|$)/i.test(m)).length;
    return { record, mechanisms, allQualifier, qualifierInfo: allQualifier?qualifiers[allQualifier.toLowerCase()]:null, lookupCount };
}

function parseDmarcRecord(raw){
    const record=String(raw||'').trim();
    if(!record) return null;
    const tags={};
    record.split(';').forEach(seg=>{
        const idx=seg.indexOf('=');
        if(idx===-1) return;
        const k=seg.slice(0,idx).trim().toLowerCase();
        const v=seg.slice(idx+1).trim();
        if(k) tags[k]=v;
    });
    const policies={
        reject:{ label:'Reject', tone:'pass', note:'Messages that fail authentication are rejected outright.' },
        quarantine:{ label:'Quarantine', tone:'warn', note:'Messages that fail authentication are routed to spam or junk.' },
        none:{ label:'Monitor Only', tone:'fail', note:'No enforcement is applied yet — failing messages are still delivered and only reports are generated.' }
    };
    const p=(tags.p||'').toLowerCase();
    const pctNum=tags.pct!==undefined?parseInt(tags.pct,10):100;
    const splitAddrs=v=>String(v||'').split(',').map(s=>s.trim().replace(/^mailto:/i,'')).filter(Boolean);
    return {
        record, tags, policy:p, policyInfo:policies[p]||null,
        subdomainPolicy:(tags.sp||'').toLowerCase()||null,
        pct:isNaN(pctNum)?100:pctNum,
        rua:splitAddrs(tags.rua), ruf:splitAddrs(tags.ruf),
        adkim:(tags.adkim||'r').toLowerCase(), aspf:(tags.aspf||'r').toLowerCase()
    };
}

function emailSecurityVerdict(spfInfo,dmarcInfo,dkimOk){
    if(!dmarcInfo){
        return { tone:'exposed', label:'Not Protected', icon:'shield-halved',
            note: spfInfo ? 'No DMARC record was found, so receiving servers have no instructions for handling messages that fail authentication.'
                          : 'Neither SPF nor DMARC is configured for this domain — it can likely be spoofed.' };
    }
    if(dmarcInfo.policy==='none'){
        return { tone:'monitor', label:'Monitoring Only', icon:'eye',
            note:'DMARC is published with p=none, so reports are collected but spoofed mail is not blocked or quarantined yet.' };
    }
    if(dmarcInfo.policy==='reject' && spfInfo && spfInfo.allQualifier==='-all' && dkimOk){
        return { tone:'strong', label:'Strongly Configured', icon:'shield-halved',
            note:'SPF, DKIM and an enforcing DMARC policy are all in place.' };
    }
    if(dmarcInfo.policy==='reject'||dmarcInfo.policy==='quarantine'){
        return { tone:'partial', label:'Partially Configured', icon:'shield-halved',
            note:'DMARC is enforcing, but SPF and/or DKIM could be tightened further.' };
    }
    return { tone:'partial', label:'Needs Attention', icon:'triangle-exclamation',
        note:'Review the records below — one or more mechanisms is missing or unrecognized.' };
}

function renderEmailSecurityResult(toolResult){
    const d=(toolResult&&toolResult.data)||toolResult||{};
    const spfRaw=d.spf||''; const dmarcRaw=d.dmarc||'';
    const dkim=d.dkim_selectors_found||{};
    const dkimKeys=Object.keys(dkim);
    const spfOk=!!spfRaw, dmarcOk=!!dmarcRaw, dkimOk=dkimKeys.length>0;
    const spfInfo=parseSpfRecord(spfRaw);
    const dmarcInfo=parseDmarcRecord(dmarcRaw);
    const verdict=emailSecurityVerdict(spfInfo,dmarcInfo,dkimOk);
    const verdictBadgeClass=verdict.tone==='strong'?'success':(verdict.tone==='exposed'?'danger':'warning');

    let dmarcTone='fail', dmarcLabel='Missing', dmarcIcon='times';
    if(dmarcOk){
        if(dmarcInfo.policy==='none'){ dmarcTone='warn'; dmarcLabel='Monitor Only'; dmarcIcon='eye'; }
        else if(dmarcInfo.policyInfo){ dmarcTone='pass'; dmarcLabel='Enforcing'; dmarcIcon='check'; }
        else { dmarcTone='warn'; dmarcLabel='Unrecognized Policy'; dmarcIcon='question'; }
    }

    const spfSection=`<div class="email-security-section">
        <div class="email-security-section-head"><h5>SPF</h5><span class="email-badge ${spfOk?'pass':'fail'}"><i class="fas fa-${spfOk?'check':'times'}"></i> ${spfOk?'Configured':'Missing'}</span></div>
        ${spfOk?`<pre style="margin:0;">${escapeHtml(spfInfo.record)}</pre>
            ${spfInfo.qualifierInfo?`<p class="email-security-detail"><strong>${escapeHtml(spfInfo.qualifierInfo.label)}</strong> — ${escapeHtml(spfInfo.qualifierInfo.note)}</p>`:`<p class="email-security-detail">No <code>all</code> mechanism was found — sender coverage may be incomplete.</p>`}
            ${spfInfo.mechanisms.length?`<div class="email-security-chips">${spfInfo.mechanisms.map(m=>`<span class="email-security-chip">${escapeHtml(m)}</span>`).join('')}</div>`:''}
            ${spfInfo.lookupCount>10?`<p class="email-security-detail" style="color:var(--red-500);"><strong>${spfInfo.lookupCount} DNS-querying mechanisms</strong> — exceeds the 10-lookup limit in RFC 7208; this record may fail to evaluate.</p>`:''}`
            :`<p class="email-security-detail">No SPF (TXT) record was found for this domain. Without one, any server can claim to send mail on its behalf.</p>`}
    </div>`;

    const dmarcSection=`<div class="email-security-section">
        <div class="email-security-section-head"><h5>DMARC</h5><span class="email-badge ${dmarcTone}"><i class="fas fa-${dmarcIcon}"></i> ${dmarcLabel}</span></div>
        ${dmarcOk?`<pre style="margin:0;">${escapeHtml(dmarcInfo.record)}</pre>
            ${dmarcInfo.policyInfo?`<p class="email-security-detail"><strong>Policy: ${escapeHtml(dmarcInfo.policyInfo.label)}</strong> — ${escapeHtml(dmarcInfo.policyInfo.note)}</p>`:`<p class="email-security-detail">The <code>p=</code> tag is missing or not one of none, quarantine, or reject.</p>`}
            ${dmarcInfo.pct<100?`<p class="email-security-detail">Enforcement applies to <strong>${dmarcInfo.pct}%</strong> of messages (<code>pct=${dmarcInfo.pct}</code>) — the remainder falls back to lighter handling.</p>`:''}
            ${dmarcInfo.subdomainPolicy&&dmarcInfo.subdomainPolicy!==dmarcInfo.policy?`<p class="email-security-detail">Subdomain policy (<code>sp=</code>) is set separately to <strong>${escapeHtml(dmarcInfo.subdomainPolicy)}</strong>.</p>`:''}
            <p class="email-security-detail" style="margin-bottom:2px;">${dmarcInfo.rua.length?'Aggregate reports (<code>rua</code>):':'No aggregate report address (<code>rua</code>) is set — visibility into abuse is limited.'}</p>
            ${dmarcInfo.rua.length?`<div class="email-security-chips">${dmarcInfo.rua.map(a=>`<span class="email-security-chip">${escapeHtml(a)}</span>`).join('')}</div>`:''}
            ${dmarcInfo.ruf.length?`<p class="email-security-detail" style="margin-bottom:2px;">Forensic reports (<code>ruf</code>):</p><div class="email-security-chips">${dmarcInfo.ruf.map(a=>`<span class="email-security-chip">${escapeHtml(a)}</span>`).join('')}</div>`:''}`
            :`<p class="email-security-detail">No DMARC record was found at <code>_dmarc</code>. Without it, receiving mail servers decide on their own how to treat spoofed mail.</p>`}
    </div>`;

    const dkimSection=`<div class="email-security-section">
        <div class="email-security-section-head"><h5>DKIM</h5><span class="email-badge ${dkimOk?'pass':'fail'}"><i class="fas fa-${dkimOk?'check':'times'}"></i> ${dkimOk?`${dkimKeys.length} Selector${dkimKeys.length!==1?'s':''}`:'None Found'}</span></div>
        ${dkimOk?dkimKeys.map(k=>{
            const v=String(dkim[k]||''); const short=v.length>140?v.slice(0,140)+'...':v;
            return `<p class="email-security-detail" style="font-family:var(--font-mono);word-break:break-all;"><span style="color:var(--steel);">${escapeHtml(k)}:</span> ${escapeHtml(short)}</p>`;
        }).join(''):`<p class="email-security-detail">No DKIM selectors were discovered from the common selector list. This does not rule out DKIM entirely — a non-standard selector name will not surface by guessing.</p>`}
    </div>`;

    return `<div class="result-card">
        <div class="result-card-header"><strong>Email Security</strong><span class="badge ${verdictBadgeClass}"><i class="fas fa-${verdict.icon}"></i> ${escapeHtml(verdict.label)}</span></div>
        <div class="email-security-verdict ${verdict.tone}"><i class="fas fa-${verdict.icon}"></i><span>${escapeHtml(verdict.note)}</span></div>
        ${spfSection}
        ${dmarcSection}
        ${dkimSection}
    </div>`;
}

function renderIpInfoResult(toolResult){
    const d = toolResult.data || toolResult;

    // ── Normalize fields (handles both backend v4.0 and v4.1) ─────
    const ip          = String(d.ip || '--');
    const country     = String(d.country || 'Unknown');
    const countryCode = String(d.country_code || '').toUpperCase();
    const city        = String(d.city || '');
    const region      = String(d.region || '');
    const postal      = String(d.postal || '');
    const lat         = (typeof d.latitude === 'number')  ? d.latitude  : null;
    const lon         = (typeof d.longitude === 'number') ? d.longitude : null;
    const tz          = String(d.timezone || '');
    const utcOff      = String(d.utc_offset || '');
    const isp         = String(d.isp || d.org || '--');
    const org         = String(d.org || d.isp || '--');

    // ASN — read every possible key shape so this never shows '--' when data exists
    let asn = String(d.asn || d.as || d.asn_number || d.as_number || '').trim();
    if(asn && !asn.toUpperCase().startsWith('AS')) asn = 'AS' + asn;

    const asnName     = String(d.asn_name || d.asname || '');
    const asnRoute    = String(d.asn_route || '');
    const asnCountry  = String(d.asn_country || '');
    const asnRegistry = String(d.asn_registry || '');
    const asnDesc     = String(d.asn_description || '');
    const domain      = String(d.domain || '');
    const rdns        = String(d.reverse_dns || '');
    const type        = String(d.type || '');
    const provider    = String(d.provider || '');
    const isProxy     = d.is_proxy   === true;
    const isHosting   = d.is_hosting === true;
    const isMobile    = d.is_mobile  === true;

    // ── Country flag emoji from ISO code ──────────────────────────
    const flagEmoji = (countryCode.length === 2)
        ? String.fromCodePoint(...[...countryCode].map(c => 0x1F1E6 + c.charCodeAt(0) - 65))
        : '';

    // ── IP version badge ──────────────────────────────────────────
    const isV6 = ip.includes(':');
    const ipVersionBadge = (ip !== '--')
        ? `<span class="badge ${isV6?'info':'success'}" style="font-size:0.62rem;padding:1px 6px;">IPv${isV6?6:4}</span>`
        : '';

    // ── Coords + map links ────────────────────────────────────────
    const hasCoords = lat !== null && lon !== null;
    const coords = hasCoords ? `${lat.toFixed(4)}, ${lon.toFixed(4)}` : '--';
    const osmUrl = hasCoords ? `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=11/${lat}/${lon}` : '';
    const gmUrl  = hasCoords ? `https://www.google.com/maps?q=${lat},${lon}` : '';

    // ── ASN link (bgp.tools is professional + clean) ──────────────
    const asnLink = asn ? `https://bgp.tools/as/${asn.replace(/^AS/i,'')}` : '';

    // ── Location line ─────────────────────────────────────────────
    const locationLine = [city, region, postal, country].filter(Boolean).join(', ') || 'Unknown location';

    // ── Privacy / type badges ─────────────────────────────────────
    const typeBadges = [];
    if(isProxy)   typeBadges.push(`<span class="badge danger"   style="font-size:0.68rem;"><i class="fas fa-user-secret"></i> Proxy / VPN</span>`);
    if(isHosting) typeBadges.push(`<span class="badge warning"  style="font-size:0.68rem;"><i class="fas fa-server"></i> Hosting / DC</span>`);
    if(isMobile)  typeBadges.push(`<span class="badge info"     style="font-size:0.68rem;"><i class="fas fa-mobile-screen"></i> Mobile</span>`);
    if(type && !isProxy && !isHosting && !isMobile)
                  typeBadges.push(`<span class="badge"          style="font-size:0.68rem;">${escapeHtml(type)}</span>`);

    // ── Build card ────────────────────────────────────────────────
    return `<div class="result-card ip-info-card">
        <div class="result-card-header">
            <strong><i class="fas fa-location-dot" style="color:var(--red-400);margin-right:6px;"></i> IP &amp; Geolocation</strong>
            <span class="badge success"><i class="fas fa-map-marker-alt"></i> ${escapeHtml(city || country || 'Resolved')}</span>
        </div>

        <div style="display:flex;align-items:center;gap:14px;padding:12px 4px 14px;border-bottom:1px solid var(--border-color);margin-bottom:12px;">
            <div style="font-size:2.2rem;line-height:1;flex-shrink:0;filter:drop-shadow(0 2px 6px rgba(0,0,0,0.35));">${flagEmoji || '<i class="fas fa-globe" style="color:var(--steel);font-size:1.6rem;"></i>'}</div>
            <div style="flex:1;min-width:0;">
                <div style="font-family:var(--font-mono);font-size:0.95rem;font-weight:700;color:var(--text-primary);word-break:break-all;">${escapeHtml(ip)} ${ipVersionBadge}</div>
                <div style="font-size:0.74rem;color:var(--text-secondary);margin-top:4px;"><i class="fas fa-map-pin" style="width:12px;color:var(--red-400);"></i> ${escapeHtml(locationLine)}</div>
                ${org && org !== '--' && org !== isp ? `<div style="font-size:0.72rem;color:var(--text-muted);margin-top:2px;"><i class="fas fa-building" style="width:12px;"></i> ${escapeHtml(org)}</div>` : ''}
            </div>
            ${osmUrl ? `<a href="${escapeHtml(osmUrl)}" target="_blank" rel="noopener" title="Open in OpenStreetMap" style="flex-shrink:0;width:34px;height:34px;border-radius:50%;background:var(--bg-tertiary);border:1px solid var(--border-color);display:flex;align-items:center;justify-content:center;color:var(--steel);text-decoration:none;transition:all 0.15s;" onmouseover="this.style.color='var(--red-400)';this.style.borderColor='var(--red-400)';" onmouseout="this.style.color='var(--steel)';this.style.borderColor='var(--border-color)';"><i class="fas fa-map"></i></a>` : ''}
        </div>

        ${typeBadges.length ? `<div style="margin-bottom:12px;display:flex;gap:6px;flex-wrap:wrap;">${typeBadges.join('')}</div>` : ''}

        <div class="port-summary-grid" style="margin-bottom:12px;">
            <div class="port-summary-card">
                <div class="port-summary-value" style="color:var(--steel);font-size:0.88rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(country)}">${escapeHtml(country)}</div>
                <div class="port-summary-label">Country</div>
            </div>
            <div class="port-summary-card">
                <div class="port-summary-value" style="color:var(--gold);font-size:0.88rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(isp)}">${escapeHtml(isp)}</div>
                <div class="port-summary-label">ISP</div>
            </div>
            <div class="port-summary-card">
                <div class="port-summary-value" style="color:var(--green);font-size:0.88rem;">${asn ? escapeHtml(asn) : '--'}</div>
                <div class="port-summary-label">ASN</div>
            </div>
            <div class="port-summary-card">
                <div class="port-summary-value" style="color:var(--amber);font-size:0.82rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(tz||'--')}">${escapeHtml(tz || '--')}</div>
                <div class="port-summary-label">Timezone</div>
            </div>
        </div>

        <table class="data-table"><tbody>
            ${asn ? `<tr>
                <td style="font-weight:600;width:32%;">ASN</td>
                <td>${asnLink
                    ? `<a href="${escapeHtml(asnLink)}" target="_blank" rel="noopener" style="color:var(--red-400);font-family:var(--font-mono);text-decoration:none;font-weight:600;">${escapeHtml(asn)} <i class="fas fa-up-right-from-square" style="font-size:0.6rem;opacity:0.6;"></i></a>`
                    : `<span style="font-family:var(--font-mono);font-weight:600;">${escapeHtml(asn)}</span>`}
                    ${asnName ? ` &nbsp;·&nbsp; <span style="font-size:0.72rem;color:var(--text-muted);">${escapeHtml(asnName)}</span>` : ''}</td>
            </tr>` : ''}
            ${asnRoute    ? `<tr><td style="font-weight:600;">BGP Route</td><td style="font-family:var(--font-mono);font-size:0.72rem;">${escapeHtml(asnRoute)}</td></tr>` : ''}
            ${asnRegistry ? `<tr><td style="font-weight:600;">Registry</td><td>${escapeHtml(asnRegistry)}</td></tr>` : ''}
            ${asnCountry  ? `<tr><td style="font-weight:600;">ASN Country</td><td>${escapeHtml(asnCountry)}</td></tr>` : ''}
            ${asnDesc     ? `<tr><td style="font-weight:600;">ASN Description</td><td style="font-size:0.74rem;color:var(--text-secondary);">${escapeHtml(asnDesc)}</td></tr>` : ''}
            <tr><td style="font-weight:600;">ISP</td><td>${escapeHtml(isp || '--')}</td></tr>
            ${org && org !== isp ? `<tr><td style="font-weight:600;">Organization</td><td>${escapeHtml(org)}</td></tr>` : ''}
            ${locationLine !== 'Unknown location' ? `<tr><td style="font-weight:600;">Location</td><td>${escapeHtml(locationLine)}</td></tr>` : ''}
            <tr><td style="font-weight:600;">Coordinates</td>
                <td style="font-family:var(--font-mono);font-size:0.72rem;">${escapeHtml(coords)}
                ${gmUrl ? `<a href="${escapeHtml(gmUrl)}" target="_blank" rel="noopener" style="color:var(--red-400);font-size:0.68rem;margin-left:6px;">[Google Maps]</a>` : ''}</td>
            </tr>
            ${tz ? `<tr><td style="font-weight:600;">Timezone</td><td>${escapeHtml(tz)}${utcOff ? ` <span style="color:var(--text-muted);font-size:0.72rem;">(${escapeHtml(utcOff)})</span>` : ''}</td></tr>` : ''}
            ${rdns ? `<tr><td style="font-weight:600;">Reverse DNS</td><td style="font-family:var(--font-mono);font-size:0.72rem;">${escapeHtml(rdns)}</td></tr>` : ''}
            ${domain && domain !== rdns ? `<tr><td style="font-weight:600;">Domain</td><td style="font-family:var(--font-mono);font-size:0.72rem;">${escapeHtml(domain)}</td></tr>` : ''}
            ${provider ? `<tr><td style="font-weight:600;">Data Source</td><td><span class="badge info" style="font-size:0.62rem;">${escapeHtml(provider)}</span></td></tr>` : ''}
        </tbody></table>
    </div>`;
}

// ─── SSL/TLS Certificate — full renderer for scan_ssl v3.0.0 ─────────────
// Formats a decoded X.509 name ({commonName, organizationName, ...}) OR a
// plain string into a single readable line. Falls back gracefully if the
// value is missing, null, or an unexpected shape.
function fmtCertName(name){
    if(name===undefined||name===null||name==='')return '--';
    if(typeof name==='string')return escapeHtml(name);
    if(typeof name!=='object')return escapeHtml(String(name));
    const order=['commonName','organizationName','organizationalUnitName',
                 'countryName','stateOrProvinceName','localityName',
                 'emailAddress','serialNumber'];
    const labels={commonName:'CN',organizationName:'O',
                  organizationalUnitName:'OU',countryName:'C',
                  stateOrProvinceName:'ST',localityName:'L',
                  emailAddress:'E',serialNumber:'SN'};
    const parts=[];
    order.forEach(k=>{ if(name[k]) parts.push(`${labels[k]||k}=${name[k]}`); });
    Object.keys(name).forEach(k=>{
        if(!order.includes(k) && name[k]) parts.push(`${k}=${name[k]}`);
    });
    return parts.length ? escapeHtml(parts.join(' · ')) : '--';
}

function renderSslResult(toolResult){
    const d = toolResult.data || toolResult;

    // ── Validity classification ────────────────────────────────────
    const isExpired    = d.is_expired === true;
    const expiringSoon = d.expiring_soon === true;
    const selfSigned   = d.self_signed === true;
    const daysLeft     = (typeof d.days_until_expiry === 'number') ? d.days_until_expiry : null;

    let validBadge, cardBorder;
    if(isExpired){
        validBadge = `<span class="badge danger"><i class="fas fa-triangle-exclamation"></i> Expired</span>`;
        cardBorder = 'var(--red-500)';
    }else if(expiringSoon){
        validBadge = `<span class="badge warning"><i class="fas fa-hourglass-half"></i> Expiring Soon</span>`;
        cardBorder = 'var(--amber)';
    }else if(selfSigned){
        validBadge = `<span class="badge warning"><i class="fas fa-user-lock"></i> Self-Signed</span>`;
        cardBorder = 'var(--amber)';
    }else{
        validBadge = `<span class="badge success"><i class="fas fa-lock"></i> Valid</span>`;
        cardBorder = 'var(--green)';
    }

    const protocolWeak = d.protocol_weak === true;
    const cipherWeak   = d.cipher_weak === true;
    const protocolColor = protocolWeak ? 'var(--amber)' : 'var(--green)';
    const cipherColor   = cipherWeak   ? 'var(--amber)' : 'var(--green)';

    const daysText = daysLeft !== null
        ? (daysLeft < 0 ? `${Math.abs(daysLeft)}d ago` : `${daysLeft}d`)
        : '--';
    const daysColor = daysLeft === null ? 'var(--text-muted)'
                    : daysLeft < 0       ? 'var(--red-500)'
                    : daysLeft <= 30     ? 'var(--amber)'
                    :                      'var(--green)';

    // ── Base card ──────────────────────────────────────────────────
    let html = `<div class="result-card" style="border-left:3px solid ${cardBorder};">
        <div class="result-card-header">
            <strong><i class="fas fa-lock" style="color:${cardBorder};margin-right:6px;"></i> SSL/TLS Certificate</strong>
            ${validBadge}
        </div>`;

    // ── Subject / Issuer (now correctly handles object shape) ──────
    html += `<table class="data-table" style="margin-bottom:10px;"><tbody>
        <tr><td style="font-weight:600;width:28%;">Subject</td><td style="font-family:var(--font-mono);font-size:0.72rem;">${fmtCertName(d.subject)}</td></tr>
        <tr><td style="font-weight:600;">Issuer</td><td style="font-family:var(--font-mono);font-size:0.72rem;">${fmtCertName(d.issuer)}</td></tr>
    </tbody></table>`;

    // ── KPI grid ───────────────────────────────────────────────────
    html += `<div class="port-summary-grid" style="margin-bottom:10px;">
        <div class="port-summary-card">
            <div class="port-summary-value" style="color:${daysColor};font-size:1.1rem;">${daysText}</div>
            <div class="port-summary-label">${daysLeft !== null && daysLeft < 0 ? 'Expired' : 'Days Left'}</div>
        </div>
        <div class="port-summary-card">
            <div class="port-summary-value" style="color:${protocolColor};font-size:1rem;">${escapeHtml(String(d.protocol||'--'))}</div>
            <div class="port-summary-label">Protocol${protocolWeak?' ⚠':''}</div>
        </div>
        <div class="port-summary-card">
            <div class="port-summary-value" style="color:var(--steel);font-size:0.9rem;">${escapeHtml(String(d.cipher_bits||'--'))}-bit</div>
            <div class="port-summary-label">Cipher Strength</div>
        </div>
        <div class="port-summary-card">
            <div class="port-summary-value" style="color:var(--gold);">${escapeHtml(String(d.chain_length||1))}</div>
            <div class="port-summary-label">Chain Certs</div>
        </div>
    </div>`;

    // ── Cipher + validity details ─────────────────────────────────
    html += `<table class="data-table"><tbody>
        <tr><td style="font-weight:600;width:28%;">Cipher Suite</td><td style="font-family:var(--font-mono);font-size:0.72rem;color:${cipherColor};">${escapeHtml(String(d.cipher_suite||'--'))}</td></tr>
        ${d.cipher_protocol?`<tr><td style="font-weight:600;">Cipher Protocol</td><td style="font-family:var(--font-mono);font-size:0.72rem;">${escapeHtml(String(d.cipher_protocol))}</td></tr>`:''}
        ${d.cipher_note?`<tr><td style="font-weight:600;">Cipher Note</td><td style="font-size:0.72rem;color:${cipherColor};">${escapeHtml(String(d.cipher_note))}</td></tr>`:''}
        ${d.protocol_note?`<tr><td style="font-weight:600;">Protocol Note</td><td style="font-size:0.72rem;color:${protocolColor};">${escapeHtml(String(d.protocol_note))}</td></tr>`:''}
        ${d.serial_number?`<tr><td style="font-weight:600;">Serial</td><td style="font-family:var(--font-mono);font-size:0.68rem;word-break:break-all;">${escapeHtml(String(d.serial_number))}</td></tr>`:''}
        ${d.valid_from?`<tr><td style="font-weight:600;">Valid From</td><td style="font-family:var(--font-mono);font-size:0.72rem;">${escapeHtml(String(d.valid_from))}</td></tr>`:''}
        ${d.valid_until?`<tr><td style="font-weight:600;">Valid Until</td><td style="font-family:var(--font-mono);font-size:0.72rem;color:${daysColor};">${escapeHtml(String(d.valid_until))}</td></tr>`:''}
        ${d.self_signed!==undefined?`<tr><td style="font-weight:600;">Self-Signed</td><td>${d.self_signed?'<span style="color:var(--amber);">Yes</span>':'<span style="color:var(--green);">No</span>'}</td></tr>`:''}
        ${d.publicly_trusted!==undefined?`<tr><td style="font-weight:600;">Publicly Trusted</td><td>${d.publicly_trusted===true?'<span style="color:var(--green);">Yes</span>':d.publicly_trusted===false?'<span style="color:var(--amber);">No</span>':'<span style="color:var(--text-muted);">Unknown</span>'}</td></tr>`:''}
    </tbody></table>`;

    // ── Public key ────────────────────────────────────────────────
    if(d.public_key && typeof d.public_key === 'object' && d.public_key.algorithm){
        const pk = d.public_key;
        html += `<div class="accordion-item" style="margin-top:12px;">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                <span><i class="fas fa-key"></i> Public Key</span>
                <i class="fas fa-chevron-down chevron"></i>
            </div>
            <div class="accordion-body">
                <table class="data-table"><tbody>
                    <tr><td style="font-weight:600;">Algorithm</td><td>${escapeHtml(String(pk.algorithm))}</td></tr>
                    ${pk.size_bits?`<tr><td style="font-weight:600;">Key Size</td><td>${escapeHtml(String(pk.size_bits))} bits</td></tr>`:''}
                    ${pk.curve?`<tr><td style="font-weight:600;">Curve</td><td>${escapeHtml(String(pk.curve))}</td></tr>`:''}
                    ${pk.exponent?`<tr><td style="font-weight:600;">Exponent</td><td>${escapeHtml(String(pk.exponent))}</td></tr>`:''}
                    ${pk.hint?`<tr><td style="font-weight:600;">Note</td><td style="font-size:0.72rem;color:var(--text-muted);">${escapeHtml(String(pk.hint))}</td></tr>`:''}
                </tbody></table>
            </div>
        </div>`;
    }

    // ── Signature algorithm + basic constraints ───────────────────
    if(d.signature_algorithm){
        html += `<table class="data-table" style="margin-top:10px;"><tbody>
            <tr><td style="font-weight:600;width:28%;">Signature Algorithm</td><td style="font-family:var(--font-mono);font-size:0.72rem;">${escapeHtml(String(d.signature_algorithm))}</td></tr>
            ${d.is_ca!==undefined&&d.is_ca!==null?`<tr><td style="font-weight:600;">CA Certificate</td><td>${d.is_ca?'Yes':'No'}</td></tr>`:''}
            ${d.path_length!==null&&d.path_length!==undefined?`<tr><td style="font-weight:600;">Path Length</td><td>${escapeHtml(String(d.path_length))}</td></tr>`:''}
        </tbody></table>`;
    }

    // ── Subject Alternative Names ─────────────────────────────────
    if(Array.isArray(d.subject_alt_names) && d.subject_alt_names.length){
        html += `<div class="accordion-item" style="margin-top:10px;">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                <span><i class="fas fa-globe"></i> Subject Alternative Names (${d.subject_alt_names.length})</span>
                <i class="fas fa-chevron-down chevron"></i>
            </div>
            <div class="accordion-body">
                <div style="display:flex;flex-wrap:wrap;gap:4px;">
                    ${d.subject_alt_names.map(san=>{
                        const t = san && san.type ? String(san.type) : '?';
                        const v = san && san.value !== undefined ? String(san.value) : '';
                        const tone = t==='DNS'?'var(--steel)'
                                   : t==='IP'?'var(--gold)'
                                   : t==='email'?'var(--amber)'
                                   : 'var(--red-400)';
                        return `<span class="record-chip"><span class="rc-type" style="color:${tone};">${escapeHtml(t)}</span><span class="rc-value">${escapeHtml(v)}</span></span>`;
                    }).join('')}
                </div>
            </div>
        </div>`;
    }

    // ── Key usage / extended key usage ────────────────────────────
    const kuList  = Array.isArray(d.key_usage) ? d.key_usage : [];
    const ekuList = Array.isArray(d.extended_key_usage) ? d.extended_key_usage : [];
    if(kuList.length || ekuList.length){
        html += `<div class="accordion-item" style="margin-top:10px;">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                <span><i class="fas fa-tasks"></i> Key Usage</span>
                <i class="fas fa-chevron-down chevron"></i>
            </div>
            <div class="accordion-body">
                ${kuList.length?`<div style="margin-bottom:8px;"><strong style="font-size:0.72rem;color:var(--steel);text-transform:uppercase;">Key Usage</strong><div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px;">${kuList.map(k=>`<span class="badge info" style="font-size:0.68rem;">${escapeHtml(String(k))}</span>`).join('')}</div></div>`:''}
                ${ekuList.length?`<div><strong style="font-size:0.72rem;color:var(--steel);text-transform:uppercase;">Extended Key Usage</strong><div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px;">${ekuList.map(k=>`<span class="badge info" style="font-size:0.68rem;">${escapeHtml(String(k))}</span>`).join('')}</div></div>`:''}
            </div>
        </div>`;
    }

    // ── Certificate policies ──────────────────────────────────────
    if(Array.isArray(d.certificate_policies) && d.certificate_policies.length){
        html += `<div class="accordion-item" style="margin-top:10px;">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                <span><i class="fas fa-scroll"></i> Certificate Policies (${d.certificate_policies.length})</span>
                <i class="fas fa-chevron-down chevron"></i>
            </div>
            <div class="accordion-body">
                <div style="font-family:var(--font-mono);font-size:0.68rem;word-break:break-all;">
                    ${d.certificate_policies.map(p=>`<div>${escapeHtml(String(p))}</div>`).join('')}
                </div>
            </div>
        </div>`;
    }

    // ── Full chain fingerprints ───────────────────────────────────
    if(Array.isArray(d.chain_fingerprints) && d.chain_fingerprints.length){
        html += `<div class="accordion-item" style="margin-top:10px;">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                <span><i class="fas fa-link"></i> Certificate Chain (${d.chain_fingerprints.length})</span>
                <i class="fas fa-chevron-down chevron"></i>
            </div>
            <div class="accordion-body" style="overflow-x:auto;">
                <table class="data-table">
                    <thead><tr><th>#</th><th>Role</th><th>Subject CN</th><th>SHA-256</th></tr></thead>
                    <tbody>
                        ${d.chain_fingerprints.map(c=>`<tr>
                            <td>${escapeHtml(String(c.index ?? '--'))}</td>
                            <td><span class="badge" style="font-size:0.68rem;">${escapeHtml(String(c.role||'--'))}</span></td>
                            <td style="font-size:0.72rem;">${escapeHtml(String(c.subject_cn||'--'))}</td>
                            <td style="font-family:var(--font-mono);font-size:0.62rem;word-break:break-all;max-width:170px;">${escapeHtml(String(c.fingerprint_sha256||'--').slice(0,28))}…</td>
                        </tr>`).join('')}
                    </tbody>
                </table>
            </div>
        </div>`;
    }

    // ── Chain validation summary ──────────────────────────────────
    const cv = d.chain_validation;
    if(cv && typeof cv === 'object'){
        const linked       = cv.linked === true;
        const hasRoot      = cv.has_root === true;
        const expiredCount = Array.isArray(cv.expired_certs) ? cv.expired_certs.length : 0;
        const nonCaCount   = Array.isArray(cv.non_ca_in_chain) ? cv.non_ca_in_chain.length : 0;
        const issues = [];
        if(!linked)     issues.push('Chain is not fully linked');
        if(!hasRoot)    issues.push('Root CA not present in chain');
        if(expiredCount)issues.push(`${expiredCount} expired cert(s) in chain`);
        if(nonCaCount)  issues.push(`${nonCaCount} non-CA cert(s) in intermediate positions`);

        const cvBadge = issues.length
            ? `<span class="badge warning" style="font-size:0.62rem;margin-left:6px;">${issues.length} issue${issues.length===1?'':'s'}</span>`
            : `<span class="badge success" style="font-size:0.62rem;margin-left:6px;">OK</span>`;

        html += `<div class="accordion-item" style="margin-top:10px;">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                <span><i class="fas fa-shield-halved"></i> Chain Validation ${cvBadge}</span>
                <i class="fas fa-chevron-down chevron"></i>
            </div>
            <div class="accordion-body">
                <table class="data-table"><tbody>
                    <tr><td style="font-weight:600;">Chain Length</td><td>${escapeHtml(String(cv.length ?? '--'))}</td></tr>
                    <tr><td style="font-weight:600;">Fully Linked</td><td>${linked?'<span style="color:var(--green);">Yes</span>':'<span style="color:var(--amber);">No</span>'}</td></tr>
                    <tr><td style="font-weight:600;">Has Root</td><td>${hasRoot?'<span style="color:var(--green);">Yes</span>':'<span style="color:var(--amber);">No</span>'}</td></tr>
                    ${cv.broken_at!==null&&cv.broken_at!==undefined?`<tr><td style="font-weight:600;">Broken At</td><td style="color:var(--red-500);">Index ${escapeHtml(String(cv.broken_at))}</td></tr>`:''}
                    <tr><td style="font-weight:600;">Expired Certs</td><td>${expiredCount}</td></tr>
                </tbody></table>
                ${issues.length?`<div style="margin-top:8px;font-size:0.72rem;color:var(--amber);"><i class="fas fa-triangle-exclamation"></i> ${issues.map(escapeHtml).join('<br>')}</div>`:''}
            </div>
        </div>`;
    }

    // ── Leaf fingerprints ─────────────────────────────────────────
    if(d.fingerprint_sha256 || d.fingerprint_sha1 || d.fingerprint_sha512){
        html += `<div class="accordion-item" style="margin-top:10px;">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                <span><i class="fas fa-fingerprint"></i> Leaf Fingerprints</span>
                <i class="fas fa-chevron-down chevron"></i>
            </div>
            <div class="accordion-body">
                ${d.fingerprint_sha256?`<div style="margin-bottom:6px;"><strong style="font-size:0.68rem;color:var(--steel);">SHA-256</strong><div style="font-family:var(--font-mono);font-size:0.68rem;word-break:break-all;">${escapeHtml(String(d.fingerprint_sha256))}</div></div>`:''}
                ${d.fingerprint_sha1?`<div style="margin-bottom:6px;"><strong style="font-size:0.68rem;color:var(--steel);">SHA-1</strong><div style="font-family:var(--font-mono);font-size:0.68rem;word-break:break-all;">${escapeHtml(String(d.fingerprint_sha1))}</div></div>`:''}
                ${d.fingerprint_sha512?`<div style="margin-bottom:6px;"><strong style="font-size:0.68rem;color:var(--steel);">SHA-512</strong><div style="font-family:var(--font-mono);font-size:0.68rem;word-break:break-all;">${escapeHtml(String(d.fingerprint_sha512))}</div></div>`:''}
                ${d.cert_size_bytes?`<div style="font-size:0.68rem;color:var(--text-muted);margin-top:6px;">Certificate size: ${escapeHtml(String(d.cert_size_bytes))} bytes</div>`:''}
            </div>
        </div>`;
    }

    // ── OCSP / AIA / CRL ──────────────────────────────────────────
    const ocspUrls  = Array.isArray(d.ocsp_urls)      ? d.ocsp_urls      : [];
    const caIssuers = Array.isArray(d.ca_issuers_urls)? d.ca_issuers_urls: [];
    const crlUrls   = Array.isArray(d.crl_urls)       ? d.crl_urls       : [];
    const hasRevocation = ocspUrls.length || caIssuers.length || crlUrls.length
                       || (d.ocsp_stapled !== undefined && d.ocsp_stapled !== null);
    if(hasRevocation){
        const stapled = d.ocsp_stapled;
        html += `<div class="accordion-item" style="margin-top:10px;">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                <span><i class="fas fa-clipboard-check"></i> Revocation &amp; Status</span>
                <i class="fas fa-chevron-down chevron"></i>
            </div>
            <div class="accordion-body">
                ${stapled!==undefined && stapled!==null
                    ? `<div style="margin-bottom:8px;"><strong style="font-size:0.68rem;color:var(--steel);">OCSP Stapling</strong><div style="font-size:0.72rem;">${stapled
                        ? '<span style="color:var(--green);"><i class="fas fa-check"></i> Supported &amp; stapled</span>'
                        : '<span style="color:var(--amber);"><i class="fas fa-times"></i> Not stapled</span>'}</div></div>`
                    : ''}
                ${ocspUrls.length?`<div style="margin-bottom:8px;"><strong style="font-size:0.68rem;color:var(--steel);">OCSP Responder(s)</strong>${ocspUrls.map(u=>`<div style="font-family:var(--font-mono);font-size:0.68rem;word-break:break-all;margin-top:2px;">${escapeHtml(String(u))}</div>`).join('')}</div>`:''}
                ${caIssuers.length?`<div style="margin-bottom:8px;"><strong style="font-size:0.68rem;color:var(--steel);">CA Issuers</strong>${caIssuers.map(u=>`<div style="font-family:var(--font-mono);font-size:0.68rem;word-break:break-all;margin-top:2px;">${escapeHtml(String(u))}</div>`).join('')}</div>`:''}
                ${crlUrls.length?`<div><strong style="font-size:0.68rem;color:var(--steel);">CRL Distribution</strong>${crlUrls.map(u=>`<div style="font-family:var(--font-mono);font-size:0.68rem;word-break:break-all;margin-top:2px;">${escapeHtml(String(u))}</div>`).join('')}</div>`:''}
            </div>
        </div>`;
    }

    // ── Top-level error (from orchestrator) ───────────────────────
    if(toolResult.error){
        html += `<div class="tr-error" style="margin-top:10px;"><i class="fas fa-circle-exclamation"></i> ${escapeHtml(String(toolResult.error))}</div>`;
    }

    html += `</div>`;
    return html;
}
function renderSubdomainResult(toolResult){
    const d=toolResult.data||toolResult;const subs=d.subdomains||[];
    const count=d.count||subs.length;const methods=d.methods_used||[];
    return `<div class="result-card"><div class="result-card-header"><strong>Subdomain Discovery</strong><span class="badge success"><i class="fas fa-search"></i> ${count} Found</span></div><div style="font-size:0.7rem;color:var(--text-muted);margin-bottom:8px;">Methods: ${methods.map(m=>`<span class="badge info">${escapeHtml(String(m))}</span>`).join(' ')}</div>${subs.length?`<div class="port-table-wrap"><table class="data-table"><thead><tr><th>#</th><th>Subdomain</th></tr></thead><tbody>${subs.map((s,i)=>`<tr><td style="color:var(--text-muted);">${i+1}</td><td style="font-family:var(--font-mono);color:var(--text-primary);">${escapeHtml(s)}</td></tr>`).join('')}</tbody></table></div>`:`<div class="empty-state">No subdomains found.</div>`}</div>`;
}

// ─── Tech Fingerprint — full renderer for scan_tech_fingerprint v3.0.0 ────
function _tfCategoryIcon(cat){
    const c = String(cat||'').toLowerCase();
    if(c.includes('cms'))                  return 'fa-cube';
    if(c.includes('e-commerce'))           return 'fa-cart-shopping';
    if(c.includes('website builder'))      return 'fa-wand-magic-sparkles';
    if(c.includes('static'))               return 'fa-file-code';
    if(c.includes('framework'))            return 'fa-layer-group';
    if(c.includes('js library'))           return 'fa-book';
    if(c.includes('css'))                  return 'fa-palette';
    if(c.includes('web server'))           return 'fa-server';
    if(c.includes('hosting'))              return 'fa-cloud';
    if(c.includes('storage')||c.includes('cdn')) return 'fa-network-wired';
    if(c.includes('language'))             return 'fa-code';
    if(c.includes('security')||c.includes('waf')) return 'fa-shield-halved';
    if(c.includes('anti-bot'))             return 'fa-robot';
    if(c.includes('analytics'))            return 'fa-chart-line';
    if(c.includes('tag manager'))          return 'fa-tags';
    if(c.includes('apm')||c.includes('monitoring')) return 'fa-gauge-high';
    if(c.includes('error'))                return 'fa-bug';
    if(c.includes('marketing'))            return 'fa-bullhorn';
    if(c.includes('support'))              return 'fa-headset';
    if(c.includes('payment'))              return 'fa-credit-card';
    if(c.includes('font')||c.includes('icon')) return 'fa-font';
    if(c.includes('search'))               return 'fa-magnifying-glass';
    if(c.includes('map'))                  return 'fa-map';
    if(c.includes('media'))                return 'fa-photo-film';
    if(c.includes('comment'))              return 'fa-comments';
    if(c.includes('a/b'))                  return 'fa-flask';
    if(c.includes('ci/cd'))                return 'fa-rocket';
    return 'fa-microchip';
}

function _tfConfidenceTone(conf){
    switch(String(conf||'').toLowerCase()){
        case 'high':   return { color:'var(--green)', bg:'var(--green-glow)', label:'High' };
        case 'medium': return { color:'var(--amber)', bg:'var(--amber-glow)', label:'Medium' };
        case 'low':    return { color:'var(--steel)', bg:'var(--steel-glow)', label:'Low' };
        default:       return { color:'var(--text-muted)', bg:'var(--bg-tertiary)', label:'Unknown' };
    }
}

function _tfEsc(s){ return escapeHtml(String(s==null?'':s)); }

function renderTechFingerprintResult(toolResult){
    const d = toolResult.data || toolResult || {};
    const detections = Array.isArray(d.detections) ? d.detections : [];
    const total      = detections.length;
    const confCounts = d.count_by_confidence || {
        high:   detections.filter(x=>x.confidence==='high').length,
        medium: detections.filter(x=>x.confidence==='medium').length,
        low:    detections.filter(x=>x.confidence==='low').length,
    };
    const server  = d.server_header || '--';
    const powered = d.powered_by   || '--';
    const finalUrl = d.final_url || toolResult.target || '--';
    const statusCode = d.status_code || '--';
    const cname = Array.isArray(d.dns_cname_chain) ? d.dns_cname_chain : [];

    // ── Header badge: total + confidence breakdown ─────────────────
    const headerBadge = total > 0
        ? `<span class="badge success"><i class="fas fa-microchip"></i> ${total} Detected</span>`
        : `<span class="badge"><i class="fas fa-minus-circle"></i> Nothing Detected</span>`;

    // ── Hero summary ───────────────────────────────────────────────
    let html = `<div class="result-card tf-card">
        <div class="result-card-header">
            <strong><i class="fas fa-microchip" style="color:var(--red-400);margin-right:6px;"></i> Technology Fingerprint</strong>
            ${headerBadge}
        </div>

        <div class="tf-target-row">
            <i class="fas fa-crosshairs"></i>
            <span class="tf-target-url">${_tfEsc(finalUrl)}</span>
            <span class="tf-status-chip">${_tfEsc(statusCode)}</span>
        </div>`;

    // ── Server / Powered-by / CNAME strip ──────────────────────────
    html += `<div class="tf-meta-strip">
        <div class="tf-meta-item">
            <span class="tf-meta-label">Server</span>
            <span class="tf-meta-value">${_tfEsc(server)}</span>
        </div>
        <div class="tf-meta-item">
            <span class="tf-meta-label">Powered By</span>
            <span class="tf-meta-value">${_tfEsc(powered)}</span>
        </div>`;
    if(cname.length){
        html += `<div class="tf-meta-item tf-meta-item-wide">
            <span class="tf-meta-label">DNS CNAME</span>
            <span class="tf-meta-value tf-mono">${cname.map(_tfEsc).join(' <i class="fas fa-arrow-right" style="font-size:0.6rem;opacity:0.5;"></i> ')}</span>
        </div>`;
    }
    html += `</div>`;

    // ── Confidence summary chips ──────────────────────────────────
    if(total > 0){
        html += `<div class="tf-conf-row">
            <div class="tf-conf-pill tf-conf-high">
                <span class="tf-conf-dot" style="background:var(--green);"></span>
                <span class="tf-conf-num">${confCounts.high}</span>
                <span class="tf-conf-label">High</span>
            </div>
            <div class="tf-conf-pill tf-conf-medium">
                <span class="tf-conf-dot" style="background:var(--amber);"></span>
                <span class="tf-conf-num">${confCounts.medium}</span>
                <span class="tf-conf-label">Medium</span>
            </div>
            <div class="tf-conf-pill tf-conf-low">
                <span class="tf-conf-dot" style="background:var(--steel);"></span>
                <span class="tf-conf-num">${confCounts.low}</span>
                <span class="tf-conf-label">Low</span>
            </div>
        </div>`;
    }

    // ── Empty state ────────────────────────────────────────────────
    if(total === 0){
        html += `<div class="scn-empty" style="margin-top:12px;">
            <i class="fas fa-info-circle"></i>
            No technologies were confidently detected. The target may be heavily
            proxied, serve only an error page, or use technologies outside the
            current signature database.
        </div></div>`;
        return html;
    }

    // ── Category grid: group detections by category ────────────────
    const byCat = {};
    for(const det of detections){
        const cat = det.category || 'Other';
        (byCat[cat] = byCat[cat] || []).push(det);
    }
    // Sort categories by highest-confidence detection first
    const confRank = { high:3, medium:2, low:1 };
    const catOrder = Object.keys(byCat).sort((a,b)=>{
        const aMax = Math.max(...byCat[a].map(x=>confRank[x.confidence]||0));
        const bMax = Math.max(...byCat[b].map(x=>confRank[x.confidence]||0));
        if(aMax !== bMax) return bMax - aMax;
        return a.localeCompare(b);
    });

    for(const cat of catOrder){
        const items = byCat[cat];
        const icon = _tfCategoryIcon(cat);
        html += `<div class="tf-category-block">
            <div class="tf-category-header">
                <i class="fas ${icon}"></i>
                <span>${_tfEsc(cat)}</span>
                <span class="tf-category-count">${items.length}</span>
            </div>
            <div class="tf-category-grid">`;

        for(const det of items){
            const tone = _tfConfidenceTone(det.confidence);
            const version = det.version ? `v${_tfEsc(det.version)}` : '';
            const evidence = Array.isArray(det.evidence) ? det.evidence : [];

            html += `<div class="tf-tech-card" data-tf-name="${_tfEsc(det.name)}">
                <div class="tf-tech-head">
                    <span class="tf-tech-name">${_tfEsc(det.name)}</span>
                    ${version ? `<span class="tf-tech-version">${version}</span>` : ''}
                </div>
                <div class="tf-tech-foot">
                    <span class="tf-tech-conf"
                          style="color:${tone.color};background:${tone.bg};border-color:${tone.color};">
                        ${tone.label}
                    </span>
                    ${evidence.length ? `
                        <button class="tf-evidence-toggle" type="button" title="Show evidence">
                            <i class="fas fa-search-plus"></i> ${evidence.length}
                        </button>
                    ` : ''}
                </div>
                ${evidence.length ? `
                    <div class="tf-evidence-list" hidden>
                        ${evidence.map(ev=>`<div class="tf-evidence-item">${_tfEsc(ev)}</div>`).join('')}
                    </div>
                ` : ''}
            </div>`;
        }
        html += `</div></div>`;
    }

    // ── Footer: favicon + probe paths ──────────────────────────────
    const footerBits = [];
    if(d.favicon_sha256){
        footerBits.push(`<span class="tf-foot-item"><i class="fas fa-image"></i> favicon SHA-256: <code>${_tfEsc(d.favicon_sha256.slice(0,16))}…</code></span>`);
    }
    if(Array.isArray(d.extra_paths_probed) && d.extra_paths_probed.length){
        footerBits.push(`<span class="tf-foot-item"><i class="fas fa-sitemap"></i> probed: <code>${d.extra_paths_probed.map(_tfEsc).join(', ')}</code></span>`);
    }
    if(typeof d.script_src_count === 'number'){
        footerBits.push(`<span class="tf-foot-item"><i class="fas fa-code"></i> ${d.script_src_count} script/link srcs</span>`);
    }
    if(footerBits.length){
        html += `<div class="tf-footer">${footerBits.join('')}</div>`;
    }

    html += `</div>`;
    return html;
}

// ─── HISTORY ────────────────────────────────────────────────
let allHistory=[];
// ╔══════════════════════════════════════════════════════════╗
// ║  ASSETS — replaces the old History table                ║
// ╚══════════════════════════════════════════════════════════╝
function fmtDuration(startedAt, finishedAt){
    const s = Math.max(0, Math.round((new Date(finishedAt||Date.now()) - new Date(startedAt)) / 1000));
    if(s < 60) return `${s}s`;
    const m = Math.floor(s/60), sec = s%60;
    return `${m}m ${sec}s`;
}
function fmtRelDate(iso){
    if(!iso) return '--';
    const d = new Date(iso);
    const diff = Date.now() - d;
    if(diff < 60000) return 'Just now';
    if(diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
    if(diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
    return d.toLocaleDateString();
}
function renderAssets(data, filter=''){
    const grid = document.getElementById('assetCardsGrid');
    const kpiTotal = document.getElementById('assetKpiTotal');
    const kpiDone  = document.getElementById('assetKpiDone');
    const kpiAvg   = document.getElementById('assetKpiAvgTime');
    const kpiTgt   = document.getElementById('assetKpiTargets');
    if(!grid) return;

    const rows = filter
        ? data.filter(h => (h.target||'').toLowerCase().includes(filter.toLowerCase()))
        : data;

    // KPIs from full dataset (not filtered)
    if(kpiTotal) kpiTotal.textContent = data.length;
    if(kpiDone)  kpiDone.textContent  = data.filter(h=>(h.status||'').toLowerCase()==='completed').length;
    if(kpiTgt)   kpiTgt.textContent   = new Set(data.map(h=>h.target)).size;
    const durSecs = data.filter(h=>h.started_at && h.finished_at)
        .map(h => (new Date(h.finished_at)-new Date(h.started_at))/1000);
    if(kpiAvg) kpiAvg.textContent = durSecs.length
        ? `${Math.round(durSecs.reduce((a,b)=>a+b,0)/durSecs.length)}s`
        : '--';

    if(!rows.length){
        grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><i class="fas fa-layer-group" style="font-size:2rem;margin-bottom:10px;color:var(--text-muted)"></i><strong>${filter?'No scans match that filter.':'No scans recorded yet.'}</strong><span>Run a Security Testing scan to see it here.</span></div>`;
        return;
    }
    // Max duration for relative bar width
    const maxDur = Math.max(1, ...durSecs);

    grid.innerHTML = rows.map((h, i) => {
        const statusRaw = (h.status||'completed').toLowerCase();
        const statusLabel = statusRaw === 'completed' ? 'Done' : statusRaw === 'running' ? 'Running' : statusRaw === 'failed' ? 'Failed' : statusRaw;
        const statusCls   = statusRaw === 'completed' ? 'done' : statusRaw === 'running' ? 'running' : 'failed';
        const durSec = h.started_at && (h.finished_at||h.updated_at)
            ? Math.max(0, Math.round((new Date(h.finished_at||h.updated_at)-new Date(h.started_at))/1000))
            : null;
        const durPct = durSec !== null ? Math.min(100, Math.round(durSec/maxDur*100)) : 0;
        const tools = Array.isArray(h.tools) ? h.tools : [];
        return `<div class="asset-card" style="animation-delay:${i*30}ms">
            <div class="asset-card-header">
                <div class="asset-card-target">${escapeHtml(h.target||'--')}</div>
                <span class="asset-card-status ${statusCls}"><i class="fas fa-${statusRaw==='completed'?'circle-check':statusRaw==='running'?'spinner spin':'circle-xmark'}"></i> ${statusLabel}</span>
            </div>
            <div class="asset-card-meta">
                <span><i class="fas fa-layer-group"></i> ${escapeHtml(h.mode||'basic')}</span>
                <span><i class="fas fa-clock"></i> ${durSec !== null ? fmtDuration(h.started_at, h.finished_at||h.updated_at) : '--'}</span>
                <span><i class="fas fa-calendar-day"></i> ${fmtRelDate(h.created_at||h.started_at)}</span>
                <span><i class="fas fa-hashtag"></i> ${escapeHtml(String(h.id||'').slice(0,8))}</span>
            </div>
            ${durSec !== null ? `<div class="asset-duration-bar"><div class="asset-duration-fill" style="width:${durPct}%"></div></div>` : ''}
            ${tools.length ? `<div class="asset-card-tools">${tools.slice(0,8).map(tool=>`<span class="asset-tool-tag">${escapeHtml(tool)}</span>`).join('')}${tools.length>8?`<span class="asset-tool-tag">+${tools.length-8}</span>`:''}</div>` : ''}
            <div class="asset-card-actions">
                <button class="btn-secondary asset-view-btn" data-id="${escapeHtml(String(h.id))}"><i class="fas fa-eye"></i> View</button>
                <button class="btn-secondary asset-del-btn" data-id="${escapeHtml(String(h.id))}" style="color:var(--red)"><i class="fas fa-trash"></i></button>
            </div>
        </div>`;
    }).join('');

    grid.querySelectorAll('.asset-view-btn').forEach(btn => btn.addEventListener('click', async ()=>{
        const id = btn.dataset.id;
        if(getStoragePref()==='local'){
            const e = getLocalHistory().find(x => String(x.id)===id);
            if(!e) return;
            document.getElementById('historyModalTitle').textContent = `Case — ${e.target}`;
            document.getElementById('historyModalBody').textContent = JSON.stringify(e.result||e, null, 2);
            document.getElementById('historyModal').hidden = false;
            return;
        }
        try{
            const rr = await fetch(`/api/history/${id}`);
            const e  = await rr.json();
            document.getElementById('historyModalTitle').textContent = `Case — ${e.target}`;
            document.getElementById('historyModalBody').textContent  = JSON.stringify(e.result||e, null, 2);
            document.getElementById('historyModal').hidden = false;
        }catch(ex){}
    }));
    grid.querySelectorAll('.asset-del-btn').forEach(btn => btn.addEventListener('click', async ()=>{
        if(!confirm('Delete this scan entry?')) return;
        const id = btn.dataset.id;
        if(getStoragePref()==='local'){
            removeLocalHistoryEntry(id);
            loadAssets();
            refreshOverview();
            showToast('Entry deleted');
            return;
        }
        try{
            await fetch(`/api/history/${id}`, { method:'DELETE' });
            loadAssets(); refreshOverview(); showToast('Entry deleted');
        }catch(ex){}
    }));
}

async function loadAssets(filter=''){
    const grid = document.getElementById('assetCardsGrid');
    if(!grid) return;
    grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1"><i class="fas fa-spinner spin"></i> Loading scans…</div>';
    try{
        if(getStoragePref()==='local'){ allHistory = getLocalHistory(); }
        else{ const r = await fetch('/api/history'); allHistory = await r.json(); }
        renderAssets(allHistory, filter);
    }catch(e){
        grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1">Could not load scan history.</div>';
    }
}
// Wire
const hSearch = document.getElementById('historySearch');
if(hSearch) hSearch.addEventListener('input', function(){ loadAssets(this.value); });
const exportBtn = document.getElementById('assetExportBtn');
if(exportBtn) exportBtn.addEventListener('click', ()=>{
    const blob = new Blob([JSON.stringify(allHistory||[], null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'emergens-assets.json'; a.click();
});
document.getElementById('closeHistoryModal').addEventListener('click',()=>document.getElementById('historyModal').hidden=true);
document.getElementById('historyModal').addEventListener('click',function(e){if(e.target===this)this.hidden=true;});

// ─── CONSOLE ────────────────────────────────────────────────
async function refreshConsole(){
    try{
        const sr=await fetch('/api/system/stats');const s=await sr.json();
        document.getElementById('statCpu').textContent=(s.cpu_percent||0).toFixed(1)+'%';
        document.getElementById('statMem').textContent=(s.memory_percent||0).toFixed(1)+'%';
        document.getElementById('statDisk').textContent=(s.disk_percent||0).toFixed(1)+'%';
        document.getElementById('cpuMini').textContent=(s.cpu_percent||0).toFixed(0)+'%';
        document.getElementById('memMini').textContent=(s.memory_percent||0).toFixed(0)+'%';
        const lr=await fetch('/api/logs?lines=40');const ld=await lr.json();const lines=ld.lines||[];
        // Structured log renderer — colour-codes by level, highlights users,
        // IPs, actions and Python tracebacks; groups consecutive traceback lines
        // under the triggering ERROR entry rather than showing them as raw noise.
        const LOG_LEVEL_RE = /^(\d{4}-\d{2}-\d{2}\s[\d:,]+)\s+\[?(INFO|WARNING|WARN|ERROR|CRITICAL|DEBUG)\]?\s+(.*)$/i;
        const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}/gi;
        const USER_RE = /User\s+'([^']+)'|by\s+"([^"]+)"|user=(\S+)|operator:\s+(\S+)/gi;

        function parseLogLine(raw){
            const m = raw.match(LOG_LEVEL_RE);
            if(!m) return null;
            const [, ts, level, msg] = m;
            return { ts, level: level.toUpperCase(), msg };
        }

        function highlightMsg(msg){
            // Escape first, then re-insert styled spans
            let s = escapeHtml(msg);
            // IPs
            s = s.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}/gi, m => `<span class="log-ip">${m}</span>`);
            // Quoted usernames
            s = s.replace(/('|")([^'"]{2,32})\1/g, (_, q, u) => `${q}<span class="log-user">${u}</span>${q}`);
            // Keywords
            s = s.replace(/\b(Scan started|Scan completed|created|deleted|approved|generated|Login|logout)\b/gi, m => `<span class="log-action">${m}</span>`);
            // Error keywords
            s = s.replace(/\b(Error|Failed|Exception|gagal|Traceback|re\.PatternError|HTTPConnectionPool)\b/gi, m => `<span class="log-err-detail">${m}</span>`);
            // Target domains after "target="
            s = s.replace(/target=([^\s,]+)/gi, (_, t) => `target=<span class="log-target">${t}</span>`);
            return s;
        }

        const html = !lines.length
            ? '<div class="log-entry"><span class="log-ts">--</span><span class="log-level INFO">INFO</span><span class="log-msg">No log entries yet.</span></div>'
            : (() => {
                const out = [];
                let tbuf = [];   // traceback buffer
                function flushTb(){
                    if(!tbuf.length) return;
                    // Show the traceback collapsed under the last ERROR
                    out[out.length-1] = out[out.length-1]
                        .replace('</div>', `<pre class="log-tb-detail">${escapeHtml(tbuf.join('\n'))}</pre></div>`);
                    tbuf = [];
                }
                for(const raw of lines){
                    // Detect Python traceback continuation lines
                    const isTraceback = /^\s+(File "|Traceback|~~~~|raise |return |^\s*\^|\w+Error:|re\.\w+Error)/.test(raw);
                    const parsed = parseLogLine(raw);
                    if(!parsed){
                        if(tbuf.length || isTraceback) { tbuf.push(raw); continue; }
                        out.push(`<div class="log-entry"><span class="log-ts"></span><span class="log-level"></span><span class="log-msg">${escapeHtml(raw)}</span></div>`);
                        continue;
                    }
                    flushTb();
                    const lvl = parsed.level;
                    const cls = ['ERROR','CRITICAL'].includes(lvl) ? 'log-error' : lvl === 'WARNING' || lvl === 'WARN' ? 'log-warn' : 'log-info';
                    out.push(`<div class="log-entry ${cls}"><span class="log-ts">${escapeHtml(parsed.ts)}</span><span class="log-level ${lvl}">${lvl}</span><span class="log-msg">${highlightMsg(parsed.msg)}</span></div>`);
                    if(['ERROR','CRITICAL'].includes(lvl)) tbuf = [];   // start fresh collect
                }
                flushTb();
                return out.join('');
            })();

        const ce=document.getElementById('consoleWindow');if(ce){ce.innerHTML=html;ce.scrollTop=ce.scrollHeight;}
        const fwLog=document.getElementById('fwConsoleLog');if(fwLog)fwLog.innerHTML=html;
    }catch(e){}
}
refreshConsole();
setInterval(()=>{
    const mainOpen=document.getElementById('section-console').classList.contains('active');
    const popupOpen=!!document.getElementById('fwConsoleLog');
    if(mainOpen||popupOpen)refreshConsole();
},4000);
setInterval(async()=>{try{const r=await fetch('/api/system/stats');const s=await r.json();document.getElementById('cpuMini').textContent=(s.cpu_percent||0).toFixed(0)+'%';document.getElementById('memMini').textContent=(s.memory_percent||0).toFixed(0)+'%';}catch(e){}},10000);

// ╔══════════════════════════════════════════════════════════╗
// ║  AI ASSISTANT — powered by api.siputzx.my.id (deepseekr1)   ║
// ╚══════════════════════════════════════════════════════════╝
// NOTE: this calls a third-party public API directly from the browser.
// It could not be verified against the live endpoint while this file was
// built (that domain isn't reachable from the environment that wrote this
// code), so the response is parsed defensively — several likely field
// names are tried before giving up, and a real network/API error is always
// shown honestly rather than a fake reply.
const AI_ENDPOINT='https://api.siputzx.my.id/api/ai/deepseekr1';
const CHAT_HISTORY_KEY='emergens-chat-history';

function getChatHistory(){try{return JSON.parse(localStorage.getItem(CHAT_HISTORY_KEY)||'[]');}catch(e){return[];}}
function setChatHistory(arr){try{localStorage.setItem(CHAT_HISTORY_KEY,JSON.stringify(arr.slice(-100)));}catch(e){}}
function appendChatHistory(role,content){const h=getChatHistory();h.push({role,content,ts:new Date().toISOString()});setChatHistory(h);return h;}

async function askSiputzxAI(promptText){
    const url=`${AI_ENDPOINT}?prompt=${encodeURIComponent(promptText)}`;
    let res;
    try{
        res=await fetch(url);
    }catch(networkErr){
        throw new Error('Could not reach the AI service (network/CORS error).');
    }
    let data;
    try{
        data=await res.json();
    }catch(parseErr){
        throw new Error(`AI service returned an unreadable response (HTTP ${res.status}).`);
    }
    if(data && (data.status===false || data.error)){
        throw new Error(data.error || 'The AI service returned an error.');
    }
    if(!res.ok){
        throw new Error(`AI service replied with HTTP ${res.status}.`);
    }
    // Defensive extraction — the exact success-field name wasn't verifiable
    // against the live API, so several common shapes are tried in order.
    // Extract text from the response, unwrapping common JSON wrapper shapes.
    function _pick(d){ return d && (d.data !== undefined ? d.data : d.result !== undefined ? d.result : d.message !== undefined ? d.message : d.response !== undefined ? d.response : d.answer !== undefined ? d.answer : d.content !== undefined ? d.content : d.output !== undefined ? d.output : null); }
    const raw = (typeof data === 'string') ? data : (_pick(data) !== null ? _pick(data) : null);
    if (raw === null || raw === undefined || raw === '') {
        throw new Error('AI service returned no readable reply text.');
    }
    let text;
    if (typeof raw === 'string') {
        text = raw;
    } else if (Array.isArray(raw)) {
        const strs = raw.filter(function(x){ return typeof x === 'string'; });
        text = strs.length ? strs.join(' ') : String(raw[0] !== undefined ? raw[0] : '');
    } else if (raw && typeof raw === 'object') {
        const firstStr = Object.values(raw).find(function(v){ return typeof v === 'string'; });
        text = firstStr !== undefined ? firstStr : JSON.stringify(raw, null, 2);
    } else {
        text = String(raw);
    }
    // Remove stray outer JSON punctuation left by some API wrappers (["..." ], etc.)
    text = text.trim().replace(/^\["|"\]$/g, '').replace(/^"([\s\S]*)"$/, '$1');
    return text || 'OK';
}

// ---- main Chat section rendering (shared history with the popup) ----
function renderChatWindow(){
    const w=document.getElementById('chatWindow');
    if(!w)return;
    const h=getChatHistory();
    w.innerHTML='';
    h.forEach(m=>addChatBubble(w,m.role,m.content));
    w.scrollTop=w.scrollHeight;
}
function addChatBubble(container,role,content){
    const row=document.createElement('div');
    row.className=`chat-row ${role}`;
    row.innerHTML=`<div class="chat-avatar ${role}"><i class="fas ${role==='assistant'?'fa-satellite-dish':'fa-user'}"></i></div><div class="chat-message ${role}"></div>`;
    row.querySelector('.chat-message').textContent=content;
    container.appendChild(row);
    container.scrollTop=container.scrollHeight;
    return row;
}
function addThinkingBubble(container){
    const row=document.createElement('div');
    row.className='chat-row assistant';
    row.innerHTML=`<div class="chat-avatar assistant"><i class="fas fa-satellite-dish"></i></div><div class="chat-message assistant thinking"><span class="chat-dot"></span><span class="chat-dot"></span><span class="chat-dot"></span></div>`;
    container.appendChild(row);
    container.scrollTop=container.scrollHeight;
    return row;
}
async function sendChatMessage(promptText,container,inputEl,sendBtn){
    if(!promptText)return;
    appendChatHistory('user',promptText);
    addChatBubble(container,'user',promptText);
    if(inputEl){inputEl.value='';inputEl.style.height='auto';}
    if(sendBtn)sendBtn.disabled=true;
    const thinkingRow=addThinkingBubble(container);
    try{
        const reply=await askSiputzxAI(promptText);
        thinkingRow.remove();
        appendChatHistory('assistant',reply);
        addChatBubble(container,'assistant',reply);
    }catch(err){
        thinkingRow.remove();
        const msg=`Could not get a reply: ${err.message}`;
        appendChatHistory('assistant',msg);
        addChatBubble(container,'assistant',msg);
    }finally{
        if(sendBtn)sendBtn.disabled=false;
    }
}
document.getElementById('chatSendBtn').addEventListener('click',()=>{
    const i=document.getElementById('chatInput');
    const t=i.value.trim();
    if(!t)return;
    sendChatMessage(t,document.getElementById('chatWindow'),i,document.getElementById('chatSendBtn'));
});
document.getElementById('chatInput').addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();document.getElementById('chatSendBtn').click();}});
document.getElementById('chatClearBtn').addEventListener('click',()=>{
    setChatHistory([]);
    document.getElementById('chatWindow').innerHTML='';
    showToast('Chat cleared');
    const fwMsgs=document.getElementById('fwChatMessages');
    if(fwMsgs)fwMsgs.innerHTML='';
});
renderChatWindow();

// ╔══════════════════════════════════════════════════════════╗
// ║  SEKOLAH SEARCH                                        ║
// ╚══════════════════════════════════════════════════════════╝
let schoolData = [];
async function loadSchoolData() {
    try {
        const res = await fetch('/static/data/school.json');
        if (!res.ok) throw new Error('Failed to load school.json');
        schoolData = await res.json();
    } catch (e) {
        console.error('Could not load school data', e);
        schoolData = [];
    }
}
loadSchoolData();

function schoolLevelBadge(s){
    const level = String(s.level||s.type||'').toLowerCase();
    if(level.includes('rendah') || level.includes('primary') || level.includes('sekolah kebangsaan')) return 'rendah';
    if(level.includes('menengah') || level.includes('secondary') || level.includes('smk') || level.includes('smjk')) return 'menengah';
    if(level.includes('tinggi') || level.includes('uum') || level.includes('university') || level.includes('kolej')) return 'tinggi';
    return 'other';
}
function schoolTypeLabel(s){
    const raw = String(s.type||s.level||'').trim();
    if(!raw) return 'Sekolah';
    return raw.length > 28 ? raw.slice(0,26)+'…' : raw;
}

function performSchoolSearch() {
    const q = (document.getElementById('schoolSearchInput').value || '').trim().toLowerCase();
    const grid = document.getElementById('schoolResults');
    const statsRow = document.getElementById('schoolStatsRow');
    const countEl = document.getElementById('schoolResultCount');
    const clearBtn = document.getElementById('schoolSearchClear');
    if(clearBtn) clearBtn.hidden = !q;
    if (!q) {
        grid.innerHTML = '<div class="empty-state"><i class="fas fa-search" style="font-size:2rem;margin-bottom:10px;color:var(--text-muted)"></i><strong>Taip nama sekolah untuk cari</strong></div>';
        if(statsRow) statsRow.hidden = true;
        return;
    }
    const results = schoolData.filter(s => (s.name||'').toLowerCase().includes(q) || (s.location||'').toLowerCase().includes(q) || (s.city||'').toLowerCase().includes(q));
    if(countEl) countEl.textContent = `Ditemui ${results.length} sekolah untuk "${q}"`;
    if(statsRow) statsRow.hidden = false;
    if (!results.length) {
        grid.innerHTML = `<div class="empty-state"><i class="fas fa-school" style="font-size:2rem;margin-bottom:10px;color:var(--text-muted)"></i><strong>Tiada padanan untuk "${escapeHtml(q)}"</strong><span>Cuba nama yang lebih ringkas atau nama kawasan.</span></div>`;
        return;
    }
    grid.innerHTML = results.slice(0, 120).map(s => {
        const badge = schoolLevelBadge(s);
        const typeLabel = schoolTypeLabel(s);
        const fields = [
            s.schoolcode && { icon:'fa-hashtag',   label:'Kod',     val: s.schoolcode },
            s.address    && { icon:'fa-location-dot', label:'Alamat', val: [s.address, s.postcode, s.city].filter(Boolean).join(', ') },
            s.phone      && { icon:'fa-phone',      label:'Telefon', val: s.phone },
            s.email      && { icon:'fa-envelope',   label:'E-mel',   val: s.email },
            s.location   && { icon:'fa-map-pin',    label:'Kawasan', val: s.location },
            s.students   && { icon:'fa-users',      label:'Murid',   val: s.students },
            s.teachers   && { icon:'fa-chalkboard-teacher', label:'Guru', val: s.teachers },
        ].filter(Boolean);
        return `<div class="school-card">
            <div class="school-card-name">${escapeHtml(s.name||'--')}</div>
            <div class="school-card-badge ${badge}">${escapeHtml(typeLabel)}</div>
            ${fields.map(f=>`<div class="school-card-detail"><i class="fas ${f.icon}" style="width:13px;text-align:center;color:var(--accent)"></i><span>${escapeHtml(String(f.val))}</span></div>`).join('')}
        </div>`;
    }).join('');
}

document.getElementById('schoolSearchBtn').addEventListener('click', performSchoolSearch);
document.getElementById('schoolSearchInput').addEventListener('keypress', e => { if(e.key==='Enter') performSchoolSearch(); });
document.getElementById('schoolSearchInput').addEventListener('input', e => {
    const clearBtn = document.getElementById('schoolSearchClear');
    if(clearBtn) clearBtn.hidden = !e.target.value.trim();
});
const schoolClearBtn = document.getElementById('schoolSearchClear');
if(schoolClearBtn) schoolClearBtn.addEventListener('click', ()=>{
    document.getElementById('schoolSearchInput').value = '';
    performSchoolSearch();
    document.getElementById('schoolSearchInput').focus();
});

// ╔══════════════════════════════════════════════════════════╗
// ║  TELEGRAM BOT INTEGRATION                               ║
// ╚══════════════════════════════════════════════════════════╝
let telegramPollInterval=null;
let telegramConnected=false;
let telegramStartTime=null;
let lastTelegramSnapshot=null;

function renderTelegramSteps(){
    const el=document.getElementById('telegramStepsGuide');
    if(!el)return;
    if(telegramConnected){el.innerHTML='';return;}
    const steps=[
        {n:1,title:t('tg_step1_title'),desc:t('tg_step1_desc')},
        {n:2,title:t('tg_step2_title'),desc:t('tg_step2_desc')},
        {n:3,title:t('tg_step3_title'),desc:t('tg_step3_desc')},
        {n:4,title:t('tg_step4_title'),desc:t('tg_step4_desc')}
    ];
    el.innerHTML=steps.map(s=>`<div class="telegram-step"><div class="telegram-step-num">${s.n}</div><strong>${s.title}</strong><span>${s.desc}</span></div>`).join('');
}

function initTelegram(){
    const saved=localStorage.getItem('emergens-telegram-connected');
    if(saved==='true'){checkTelegramStatus();}
}

async function checkTelegramStatus(){
    try{
        const r=await fetch('/api/telegram/status');
        const d=await r.json();
        if(d.connected){showTelegramConnected(d);startTelegramPolling();}
        else{showTelegramDisconnected();}
    }catch(e){showTelegramDisconnected();}
}

function showTelegramConnected(data){
    telegramConnected=true;
    lastTelegramSnapshot=data;
    document.getElementById('telegramDisconnected').hidden=true;
    document.getElementById('telegramConnected').hidden=false;
    document.getElementById('telegramStatusBadge').textContent='Connected';
    document.getElementById('telegramStatusBadge').className='badge success';
    document.getElementById('telegramConnectedUsername').childNodes[0].textContent=(data.username||'@unknown')+' ';
    document.getElementById('telegramChatCount').textContent=(data.chat_ids||[]).length;
    document.getElementById('telegramMsgCount').textContent=data.messages_today||0;
    document.getElementById('telegramModeDisplay').textContent=data.public_mode?'Public':'Private';
    document.getElementById('telegramPublicModeEdit').checked=data.public_mode;
    document.getElementById('telegramOwnerIdEdit').value=data.owner_id||'';
    if(data.started_at){telegramStartTime=new Date(data.started_at);}
    renderChatList(data.chat_ids||[],data.owner_id);
    updateTelegramUptime();
    renderTelegramSteps();
    localStorage.setItem('emergens-telegram-connected','true');
    updateTelegramPopup();
}

function showTelegramDisconnected(){
    telegramConnected=false;
    lastTelegramSnapshot=null;
    document.getElementById('telegramDisconnected').hidden=false;
    document.getElementById('telegramConnected').hidden=true;
    document.getElementById('telegramStatusBadge').textContent='Disconnected';
    document.getElementById('telegramStatusBadge').className='badge';
    if(telegramPollInterval){clearInterval(telegramPollInterval);telegramPollInterval=null;}
    telegramStartTime=null;
    renderTelegramSteps();
    localStorage.removeItem('emergens-telegram-connected');
    updateTelegramPopup();
}

function renderChatList(chatIds,ownerId){
    const container=document.getElementById('telegramChatList');
    if(!chatIds.length){
        container.innerHTML=`<div class="empty-state" style="padding:20px;"><i class="fas fa-inbox" style="font-size:1.5rem;color:var(--text-muted);"></i><strong>${t('tg_no_chats')}</strong><span class="hint">${t('tg_no_chats_hint')}</span></div>`;
        return;
    }
    container.innerHTML=chatIds.map(id=>{
        const isOwner=String(id)===String(ownerId);
        return `<div class="telegram-chat-row">
            <span style="display:flex;align-items:center;gap:8px;">
                <i class="fas fa-user" style="color:var(--steel);"></i>
                <code>${id}</code>
                ${isOwner?'<span class="telegram-owner-tag">Owner</span>':''}
                <span class="copy-chip" data-copy="${id}"><i class="fas fa-copy"></i> Copy</span>
            </span>
            <span style="font-size:0.68rem;color:var(--green);"><span class="live-dot" style="display:inline-block;margin-right:4px;width:6px;height:6px;"></span>Active</span>
        </div>`;
    }).join('');
    container.querySelectorAll('.copy-chip').forEach(chip=>chip.addEventListener('click',()=>{
        const val=chip.dataset.copy;
        if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(val).then(()=>showToast('Chat ID copied.')).catch(()=>showToast('Could not copy.','error'));}
    }));
}

function updateTelegramUptime(){
    if(!telegramStartTime)return;
    const el=document.getElementById('telegramUptime');
    if(!el)return;
    const diff=Math.floor((Date.now()-telegramStartTime.getTime())/1000);
    const h=Math.floor(diff/3600),m=Math.floor((diff%3600)/60),s=diff%60;
    el.textContent=h>0?`${h}h ${m}m`:`${m}m ${s}s`;
}

function startTelegramPolling(){
    if(telegramPollInterval)clearInterval(telegramPollInterval);
    telegramPollInterval=setInterval(async()=>{
        if(!telegramConnected){clearInterval(telegramPollInterval);return;}
        try{
            const r=await fetch('/api/telegram/status');
            const d=await r.json();
            if(d.connected){
                lastTelegramSnapshot=d;
                document.getElementById('telegramChatCount').textContent=(d.chat_ids||[]).length;
                document.getElementById('telegramMsgCount').textContent=d.messages_today||0;
                document.getElementById('telegramModeDisplay').textContent=d.public_mode?'Public':'Private';
                renderChatList(d.chat_ids||[],d.owner_id);
                updateTelegramUptime();
                updateTelegramPopup();
            }else{showTelegramDisconnected();}
        }catch(e){}
    },5000);
}

document.getElementById('telegramConnectBtn').addEventListener('click',async()=>{
    const token=document.getElementById('telegramBotToken').value.trim();
    const username=document.getElementById('telegramBotUsername').value.trim();
    const ownerId=document.getElementById('telegramOwnerId').value.trim();
    const publicMode=document.getElementById('telegramPublicMode').checked;
    const errorEl=document.getElementById('telegramConnectError');
    if(!token||!username){errorEl.textContent='Bot token and username are required.';errorEl.hidden=false;return;}
    errorEl.hidden=true;
    const btn=document.getElementById('telegramConnectBtn');
    btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner spin"></i> Connecting...';
    try{
        const r=await fetch('/api/telegram/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,username,owner_id:ownerId,public_mode:publicMode})});
        const d=await r.json();
        if(d.error){errorEl.textContent=d.error;errorEl.hidden=false;btn.disabled=false;btn.innerHTML='<i class="fas fa-plug"></i> Connect Bot';return;}
        showTelegramConnected(d);startTelegramPolling();showToast('Telegram bot connected successfully!');
    }catch(e){errorEl.textContent='Failed to connect. Check your server logs.';errorEl.hidden=false;btn.disabled=false;btn.innerHTML='<i class="fas fa-plug"></i> Connect Bot';}
});

document.getElementById('telegramDisconnectBtn').addEventListener('click',async()=>{
    try{await fetch('/api/telegram/disconnect',{method:'POST'});showTelegramDisconnected();showToast('Bot disconnected.');}
    catch(e){showToast('Failed to disconnect.','error');}
});

document.getElementById('telegramUpdateOwnerBtn').addEventListener('click',async()=>{
    const ownerId=document.getElementById('telegramOwnerIdEdit').value.trim();
    try{const r=await fetch('/api/telegram/update-settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({owner_id:ownerId})});const d=await r.json();if(d.error){showToast(d.error,'error');return;}showToast('Owner ID updated.');}
    catch(e){showToast('Update failed.','error');}
});

document.getElementById('telegramUpdateModeBtn').addEventListener('click',async()=>{
    const publicMode=document.getElementById('telegramPublicModeEdit').checked;
    try{const r=await fetch('/api/telegram/update-settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({public_mode:publicMode})});const d=await r.json();if(d.error){showToast(d.error,'error');return;}document.getElementById('telegramModeDisplay').textContent=publicMode?'Public':'Private';showToast(`Bot set to ${publicMode?'Public':'Private'} mode.`);}
    catch(e){showToast('Mode update failed.','error');}
});

document.getElementById('telegramBroadcastBtn').addEventListener('click',async()=>{
    const msg=document.getElementById('telegramBroadcastMsg').value.trim();
    if(!msg){showToast('Enter a message.','error');return;}
    try{const r=await fetch('/api/telegram/broadcast',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg})});const d=await r.json();document.getElementById('telegramBroadcastMsg').value='';showToast(d.error?d.error:`Sent to ${d.count||0} chat(s).`);}
    catch(e){showToast('Broadcast failed.','error');}
});

// ╔══════════════════════════════════════════════════════════╗
// ║  DOCUMENTATION — expanded, professional reference          ║
// ╚══════════════════════════════════════════════════════════╝
const docsData=[
    {cat:"Getting Started",title:"Welcome to Emergens",desc:"Emergens is a passive reconnaissance console built for domains and infrastructure you own or are explicitly authorized to test. Every module here — WHOIS, DNS, TLS, HTTP headers, and more — queries publicly available records rather than attempting to breach or bypass any system. Start from the Overview tab with a Quick Scan, then move to the Security Testing suite once you need finer control over which modules run and in what mode."},
    {cat:"Getting Started",title:"Basic vs. Expert Mode",desc:"Basic Mode runs a lighter, faster pass across the most common checks and is a good default for a first look at a target. Expert Mode enables deeper checks — including full port ranges, extended subdomain enumeration, and more exhaustive header analysis — at the cost of a longer scan time. Choose Expert Mode when you need a thorough audit trail rather than a quick sanity check."},
    {cat:"Reconnaissance",title:"WHOIS Lookup",desc:"Queries the public WHOIS record for a domain and returns the registrar, creation and expiration dates, and authoritative name servers. This is useful for confirming domain ownership, tracking upcoming expirations that could lead to accidental lapses, and understanding who is formally responsible for a zone before you report a finding."},
    {cat:"Reconnaissance",title:"DNS Records",desc:"Resolves A, AAAA, MX, TXT, NS, CNAME, and SOA records for the target domain. Reviewing the full record set helps you map mail infrastructure, third-party integrations referenced in TXT records, and the authoritative servers responsible for the zone — all from data the domain owner has already published."},
    {cat:"Reconnaissance",title:"Subdomain Discovery",desc:"Enumerates subdomains primarily via Certificate Transparency logs, surfacing hosts that have had a public TLS certificate issued for them. This is a passive technique — it never brute-forces or actively probes hostnames — and is typically the fastest way to build an initial map of an organization's public-facing footprint."},
    {cat:"Reconnaissance",title:"IP & Geolocation",desc:"Resolves the target's IP address and enriches it with ISP, ASN, organization, and approximate geographic data. Useful for understanding whether a service is self-hosted, sitting behind a CDN, or hosted with a particular cloud provider — which in turn shapes what kind of testing and disclosure process is appropriate."},
    {cat:"Network",title:"Port Scan",desc:"Checks a configurable list of TCP ports for open connections and reports the service typically associated with each open port, along with response latency. Basic Mode checks the most common service ports; Expert Mode extends coverage significantly. Always confirm you have authorization before scanning infrastructure that is not directly yours — even passive port checks can trigger alerts on monitored networks."},
    {cat:"Network",title:"Connectivity Check",desc:"Sends a series of lightweight probes to the resolved IP and reports success rate, packet loss, and latency statistics (minimum, average, maximum). This module is a good first step when a target appears to be down — it helps distinguish between a genuine outage, network-level filtering, and a slow-but-reachable host."},
    {cat:"Web Security",title:"HTTP Security Headers",desc:"Audits the response headers returned by a web server against a checklist of modern protections — including HSTS, Content-Security-Policy, X-Frame-Options, and cookie flags such as Secure, HttpOnly, and SameSite. Results are scored, categorized by severity, and paired with plain-language descriptions so findings can be shared directly with a development team."},
    {cat:"Web Security",title:"SSL/TLS Certificate",desc:"Retrieves the certificate presented by a target's TLS endpoint and reports the issuing authority, validity window, and overall validity status. Regularly checking certificate expiry across a fleet of domains helps prevent the kind of last-minute outages that expired certificates commonly cause."},
    {cat:"Web Security",title:"Email Security (SPF / DKIM / DMARC)",desc:"Verifies whether a domain has published SPF, DKIM, and DMARC records, which together are the primary defenses against email spoofing sent 'from' that domain. Missing or misconfigured records here are a common and high-impact finding, since they can allow convincing phishing email to be sent using a legitimate organization's name."},
    {cat:"Web Security",title:"Technology Fingerprint",desc:"Passively identifies frameworks, CMS platforms, and server software in use, based on response headers and publicly visible markers. This helps prioritize testing effort by surfacing known technology stacks, and is often the fastest way to confirm whether a target is running outdated, end-of-life software."},
    {cat:"Automation",title:"Telegram Bot",desc:"Link a Telegram bot to Emergens to trigger scans, review history, and receive results without opening the console. Public Mode allows any chat that messages the bot to use it; Owner-only Mode restricts every command to the configured Owner Chat ID. Treat the bot token like a password — anyone who has it can control the bot."},
    {cat:"Automation",title:"API Keys",desc:"Generate scoped API keys to call Emergens programmatically from scripts, CI/CD pipelines, or your own tooling. Keys are shown once at creation time — store them in a secrets manager rather than in source control — and can be revoked individually at any time from the API Keys panel."},
    {cat:"Data Tools",title:"Sekolah Search",desc:"A searchable directory of Malaysian primary and secondary schools, covering publicly listed details such as school code, address, contact information, and enrolment figures. This module is intended for administrative and research use — for example, locating official contact details for a school rather than looking up individuals."},
    {cat:"Preferences",title:"Data Storage: Server vs. Local",desc:"By default, scan history is stored server-side and tied to your account, so it follows you across devices. Switching to Local storage keeps history entirely inside this browser's local storage instead — nothing is sent to or read from the server for history purposes. Local history can be exported to a JSON file at any time, or cleared entirely from the Preferences panel."},
    {cat:"Preferences",title:"Interface Language",desc:"The console interface can be displayed in English or Bahasa Malaysia. This affects menus, buttons, panel titles, and static labels throughout the app; live results returned by the server — scan output, logs, and chat replies — are always shown exactly as received, regardless of the selected interface language."},
    {cat:"Best Practices & Ethics",title:"Scope Before You Scan",desc:"Only run scans against domains and infrastructure you own outright, or for which you hold a signed authorization or bug-bounty scope agreement. Passive reconnaissance is generally lower-risk than active exploitation, but WHOIS lookups, port scans, and repeated requests can still be logged, rate-limited, or flagged by the target's monitoring systems."},
    {cat:"Best Practices & Ethics",title:"Responsible Disclosure",desc:"If a scan surfaces a genuine vulnerability on a system you're authorized to test, report it through the organization's published security contact or bug bounty program rather than publicizing it. Give the owner reasonable time to remediate before any public disclosure, and avoid accessing, modifying, or exfiltrating data beyond what's needed to demonstrate the issue."},
    {cat:"FAQ",title:"Why did my scan return partial results?",desc:"Some modules depend on external services — Certificate Transparency logs, WHOIS servers — that can rate-limit or time out independently of Emergens. A partial result set usually means one module failed to respond in time; re-running the scan, or switching to Basic Mode, often resolves transient issues."},
    {cat:"FAQ",title:"Can I use Emergens against a domain I don't own?",desc:"Only with explicit written authorization, such as a signed penetration-test agreement or an active bug bounty program that names the domain in scope. Running scans against infrastructure without permission may violate computer-misuse laws in your jurisdiction, even when every module used is purely passive."}
];
function renderDocs(filter){
    const a=document.getElementById('docsAccordion');
    if(!a)return;
    const f=(filter||'').toLowerCase().trim();
    const filtered=docsData.filter(d=>!f||d.title.toLowerCase().includes(f)||d.desc.toLowerCase().includes(f)||d.cat.toLowerCase().includes(f));
    const countEl=document.getElementById('docsCountBadge');
    if(countEl)countEl.textContent=`${filtered.length} / ${docsData.length} topics`;
    const emptyEl=document.getElementById('docsEmptyState');
    if(emptyEl)emptyEl.style.display=filtered.length?'none':'block';
    a.innerHTML='';
    let lastCat=null;
    filtered.forEach(d=>{
        if(d.cat!==lastCat){lastCat=d.cat;const h=document.createElement('div');h.className='docs-cat';h.textContent=d.cat;a.appendChild(h);}
        const item=document.createElement('div');item.className='accordion-item';
        item.innerHTML=`<div class="accordion-header"><span>${d.title}</span><i class="fas fa-chevron-down chevron"></i></div><div class="accordion-body">${d.desc}</div>`;
        item.querySelector('.accordion-header').addEventListener('click',()=>item.classList.toggle('open'));
        a.appendChild(item);
    });
}
renderDocs('');
document.getElementById('docsSearchInput').addEventListener('input',function(){renderDocs(this.value);});

// ─── USERS & API KEYS ──────────────────────────────────────
async function loadUsers(){
    if(currentUserRole!=='owner')return;
    const tb=document.getElementById('usersTableBody');
    try{const r=await fetch('/api/settings/users');const u=await r.json();const me=document.getElementById('sidebarUsername')?.textContent||'';if(!u.length){tb.innerHTML=`<tr><td colspan="6"><div class="empty-state">${emptyCrest}<strong>No users loaded</strong></div></td></tr>`;return;}tb.innerHTML=u.map(usr=>{const keyCount=getUserApiKeyCount(usr);const reqCount=getUserRequestCount(usr);return `<tr><td style="color:var(--text-primary);font-weight:600;">${escapeHtml(usr.username)}</td><td><span class="badge">${escapeHtml(usr.role)}</span></td><td>${new Date(usr.created_at).toLocaleDateString()}</td><td><span class="badge info"><i class="fas fa-key"></i> ${keyCount===null?'--':keyCount}</span></td><td style="font-family:var(--font-mono);">${reqCount===null?'--':reqCount.toLocaleString()}</td><td style="display:flex;gap:6px;align-items:center;">${usr.username===me?'<span style="color:var(--text-muted);font-size:0.72rem;">(you)</span>':`<button class="icon-btn-sm" data-view-keys="${escapeHtml(usr.username)}" title="${t('th_view_keys')}: ${escapeHtml(usr.username)}"><i class="fas fa-eye"></i></button><button class="icon-btn-sm" style="color:var(--red-500);" data-del="${escapeHtml(usr.username)}"><i class="fas fa-trash"></i></button>`}</td></tr>`;}).join('');tb.querySelectorAll('[data-del]').forEach(b=>b.addEventListener('click',async()=>{try{await fetch(`/api/settings/users/${encodeURIComponent(b.dataset.del)}`,{method:'DELETE'});loadUsers();showToast('User deleted');}catch(e){showToast('Delete failed','error');}}));tb.querySelectorAll('[data-view-keys]').forEach(b=>b.addEventListener('click',()=>openUserKeysModal(b.dataset.viewKeys)));}catch(e){tb.innerHTML='<tr><td colspan="6">Could not load users.</td></tr>';}
}
function getUserApiKeyCount(u){const v=u.api_key_count??u.apiKeyCount??u.key_count??u.keys_count??u.total_keys;return typeof v==='number'?v:null;}
function getUserRequestCount(u){const v=u.total_requests??u.request_count??u.api_requests??u.requests_count??u.usage_count;return typeof v==='number'?v:null;}
function openUserKeysModal(username){
    if(currentUserRole!=='owner')return;
    document.getElementById('userKeysModalTitle').textContent=`${t('th_api_keys')} — ${username}`;
    const body=document.getElementById('userKeysModalBody');
    body.style.fontFamily='var(--font-ui)';body.style.whiteSpace='normal';
    body.innerHTML=`<div class="empty-state"><i class="fas fa-spinner fa-spin"></i> <span>${t('userkeys_modal_loading')}</span></div>`;
    document.getElementById('userKeysModal').hidden=false;
    fetchUserKeys(username);
}
function closeUserKeysModal(){document.getElementById('userKeysModal').hidden=true;}
document.getElementById('closeUserKeysModal').addEventListener('click',closeUserKeysModal);
document.getElementById('userKeysModal').addEventListener('click',function(e){if(e.target===this)closeUserKeysModal();});
async function fetchUserKeys(username){
    const body=document.getElementById('userKeysModalBody');
    try{
        const r=await fetch(`/api/settings/users/${encodeURIComponent(username)}/api-keys`);
        if(!r.ok)throw new Error('not available');
        const keys=await r.json();
        if(!Array.isArray(keys)||!keys.length){body.innerHTML=`<div class="empty-state">${emptyCrest}<strong>${t('userkeys_modal_empty')}</strong></div>`;return;}
        const maxReq=keys.reduce((m,k)=>Math.max(m,getKeyRequestCount(k)),0);
        body.innerHTML=`<table class="data-table"><thead><tr><th>${t('th_key_prefix')}</th><th>${t('th_created')}</th><th>${t('th_last_used')}</th><th>${t('th_requests')}</th></tr></thead><tbody>${keys.map(k=>{const rc=getKeyRequestCount(k);const bp=maxReq>0?Math.max(4,Math.round((rc/maxReq)*100)):0;return `<tr><td style="font-family:var(--font-mono);color:var(--text-primary);">${k.prefix||(k.key?k.key.slice(0,20)+'****':'--')}</td><td>${k.created||'--'}</td><td>${k.last_used||'--'}</td><td><div style="display:flex;align-items:center;gap:8px;min-width:100px;"><span style="font-family:var(--font-mono);font-weight:600;">${rc.toLocaleString()}</span><div class="latency-bar" style="flex:1;margin-top:0;"><div class="latency-bar-fill" style="width:${bp}%;background:linear-gradient(90deg,var(--steel),var(--red-400));"></div></div></div></td></tr>`;}).join('')}</tbody></table>`;
    }catch(e){
        body.innerHTML=`<div class="empty-state"><i class="fas fa-circle-info" style="font-size:1.4rem;color:var(--text-muted);"></i><strong>${t('userkeys_modal_error')}</strong><span class="hint">Expects <code style="background:var(--bg-tertiary);padding:1px 5px;border-radius:4px;">GET /api/settings/users/&lt;username&gt;/api-keys</code> on the server.</span></div>`;
    }
}
document.getElementById('createAccountForm').addEventListener('submit',async function(e){e.preventDefault();const u=document.getElementById('newUsername').value.trim();const r=document.getElementById('newRole').value;if(!u||!r)return showToast('Fill all fields','error');try{const res=await fetch('/api/settings/create-account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,role:r})});const d=await res.json();if(d.error){showToast(d.error,'error');return;}const c=document.getElementById('createResult');c.hidden=false;c.innerHTML=`<div class="credential-row"><span>Username</span><code>${d.username}</code></div><div class="credential-row"><span>Password</span><code style="color:var(--gold);">${d.password}</code></div><div class="credential-row"><span>Role</span><span class="badge">${d.role}</span></div><p class="reveal-warning">Copy this password now — it will not be shown again.</p>`;this.reset();loadUsers();showToast('Account created');}catch(e){showToast('Could not create account','error');}});
function conditionalLoadUsers(){if(currentUserRole==='owner')loadUsers();}

let currentApiKeyCount=0;
function getKeyRequestCount(k){const v=k.request_count??k.requests??k.total_requests??k.usage_count??k.requestCount??k.hits;return typeof v==='number'?v:0;}
async function loadApiKeys(){
    const tb=document.getElementById('apiKeysTableBody'),limitMsg=document.getElementById('apiKeyLimitMsg'),genBtn=document.getElementById('generateApiKeyBtn');
    try{const r=await fetch('/api/settings/api-keys');const keys=await r.json();currentApiKeyCount=keys.length;if(currentUserRole==='analyst'&&currentApiKeyCount>=2){genBtn.disabled=true;limitMsg.textContent='Maximum 2 API keys reached.';}else{genBtn.disabled=false;limitMsg.textContent='';}
        const totalReq=keys.reduce((s,k)=>s+getKeyRequestCount(k),0);
        const maxReq=keys.reduce((m,k)=>Math.max(m,getKeyRequestCount(k)),0);
        const topKey=keys.slice().sort((a,b)=>getKeyRequestCount(b)-getKeyRequestCount(a))[0];
        const elTK=document.getElementById('apiStatTotalKeys');if(elTK)elTK.textContent=keys.length;
        const elTR=document.getElementById('apiStatTotalRequests');if(elTR)elTR.textContent=totalReq.toLocaleString();
        const elMA=document.getElementById('apiStatMostActive');if(elMA)elMA.textContent=(keys.length&&maxReq>0)?(topKey.prefix||(topKey.key?topKey.key.slice(0,14)+'****':'--')):'--';
        const elAV=document.getElementById('apiStatAvgRequests');if(elAV)elAV.textContent=keys.length?Math.round(totalReq/keys.length).toLocaleString():'--';
        if(!keys.length){tb.innerHTML=`<tr><td colspan="5"><div class="empty-state">${emptyCrest}<strong>No API keys yet</strong><span class="hint">Generate a key to start integrating Emergens.</span></div></td></tr>`;renderAccountSummary();return;}tb.innerHTML=keys.map(k=>{const reqCount=getKeyRequestCount(k);const barPct=maxReq>0?Math.max(4,Math.round((reqCount/maxReq)*100)):0;return `<tr><td style="font-family:var(--font-mono);color:var(--text-primary);">${k.prefix||k.key?.slice(0,20)+'****'}</td><td>${k.created||'--'}</td><td>${k.last_used||'--'}</td><td><div style="display:flex;align-items:center;gap:8px;min-width:110px;"><span style="font-family:var(--font-mono);font-weight:600;color:var(--text-primary);min-width:34px;">${reqCount.toLocaleString()}</span><div class="latency-bar" style="flex:1;margin-top:0;"><div class="latency-bar-fill" style="width:${barPct}%;background:linear-gradient(90deg,var(--steel),var(--red-400));"></div></div></div></td><td><button class="icon-btn-sm" style="color:var(--red-500);" data-revoke="${k.prefix||k.key?.slice(0,20)}"><i class="fas fa-trash"></i></button></td></tr>`;}).join('');tb.querySelectorAll('[data-revoke]').forEach(b=>b.addEventListener('click',async()=>{try{await fetch(`/api/settings/api-keys/${encodeURIComponent(b.dataset.revoke)}`,{method:'DELETE'});loadApiKeys();showToast('API key revoked');}catch(e){showToast('Revoke failed','error');}}));renderAccountSummary();}catch(e){tb.innerHTML='<tr><td colspan="5">Could not load API keys.</td></tr>';}
}
window.addEventListener('section-change',(e)=>{ if(e.detail==='overview')loadApiKeys(); });
document.getElementById('generateApiKeyBtn').addEventListener('click',async()=>{
    if(currentUserRole==='analyst'&&currentApiKeyCount>=2){showToast('Analyst accounts can only create 2 API keys.','error');return;}
    const btn=document.getElementById('generateApiKeyBtn');const origHtml=btn.innerHTML;
    btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i><span>Generating...</span>';
    try{
        const r=await fetch('/api/settings/api-keys',{method:'POST'});
        const d=await r.json();
        if(d.error){showToast(d.error,'error');btn.innerHTML=origHtml;btn.disabled=false;return;}
        document.getElementById('apiKeyResult').innerHTML=`<div style="background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:var(--radius-sm);padding:14px;margin-bottom:8px;animation:fadeSlideUp 0.35s ease both;"><span style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">Your New API Key</span><br><code style="font-family:var(--font-mono);font-size:0.78rem;color:var(--gold);word-break:break-all;">${d.key}</code><p class="reveal-warning">Copy this key now — the server will not show it again. A local copy has also been saved below, on this browser.</p></div>`;
        saveRecentKey(d.key,d.prefix);
        btn.innerHTML=origHtml;
        await loadApiKeys();
        showToast('API key generated');
    }catch(e){showToast('Could not generate key','error');btn.innerHTML=origHtml;btn.disabled=false;}
});

// ─── RECENTLY GENERATED KEYS (local convenience cache — this browser only) ──
const RECENT_KEYS_STORAGE='emergens-recent-keys';
function getRecentKeys(){try{return JSON.parse(localStorage.getItem(RECENT_KEYS_STORAGE)||'[]');}catch(e){return[];}}
function setRecentKeys(arr){try{localStorage.setItem(RECENT_KEYS_STORAGE,JSON.stringify(arr));}catch(e){}}
function saveRecentKey(fullKey,prefix){
    if(!fullKey)return;
    const arr=getRecentKeys().filter(k=>k.key!==fullKey);
    arr.unshift({key:fullKey,prefix:prefix||(fullKey.slice(0,20)+'****'),saved_at:new Date().toISOString()});
    setRecentKeys(arr.slice(0,10));
    renderRecentKeys();
}
function forgetRecentKey(fullKey){setRecentKeys(getRecentKeys().filter(k=>k.key!==fullKey));renderRecentKeys();}
function timeAgo(iso){
    const diff=Math.max(0,Date.now()-new Date(iso).getTime());
    const mins=Math.floor(diff/60000);
    if(mins<1)return 'just now';
    if(mins<60)return `${mins}m ago`;
    const hrs=Math.floor(mins/60);
    if(hrs<24)return `${hrs}h ago`;
    return `${Math.floor(hrs/24)}d ago`;
}
function renderRecentKeys(){
    const el=document.getElementById('recentKeysList');
    if(!el)return;
    const arr=getRecentKeys();
    if(!arr.length){el.innerHTML=`<div class="empty-state">${emptyCrest}<strong>${t('recent_keys_empty')}</strong></div>`;return;}
    el.innerHTML=arr.map(k=>`<div class="recent-key-row"><div class="rk-icon"><i class="fas fa-key"></i></div><div class="rk-body"><code>${escapeHtml(k.key)}</code><div class="rk-meta">${t('recent_keys_saved_label')} ${timeAgo(k.saved_at)}</div></div><div class="rk-actions"><button class="icon-btn-sm" data-copy-key="${escapeHtml(k.key)}" title="Copy"><i class="fas fa-copy"></i></button><button class="icon-btn-sm" style="color:var(--red-500);" data-forget-key="${escapeHtml(k.key)}" title="${t('btn_forget_key')}"><i class="fas fa-times"></i></button></div></div>`).join('');
    el.querySelectorAll('[data-copy-key]').forEach(b=>b.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(b.dataset.copyKey);showToast('Copied to clipboard');}catch(e){showToast('Could not copy','error');}}));
    el.querySelectorAll('[data-forget-key]').forEach(b=>b.addEventListener('click',()=>forgetRecentKey(b.dataset.forgetKey)));
}
document.getElementById('clearRecentKeysBtn').addEventListener('click',()=>{
    if(!getRecentKeys().length){showToast('Nothing to clear.','error');return;}
    if(!confirm('Clear all locally saved API keys from this browser? This cannot be undone.'))return;
    setRecentKeys([]);renderRecentKeys();showToast('Saved keys cleared.');
});

// ╔══════════════════════════════════════════════════════════╗
// ║  PREFERENCES — storage choice + language                  ║
// ╚══════════════════════════════════════════════════════════╝
document.getElementById('storageChoiceServer').addEventListener('click',()=>{setStoragePref('server');initStorageChoice();showToast('Switched to server storage.');refreshOverview();if(document.getElementById('section-assets').classList.contains('active'))loadAssets(document.getElementById('historySearch').value);});
document.getElementById('storageChoiceLocal').addEventListener('click',()=>{setStoragePref('local');initStorageChoice();showToast('Switched to local browser storage.');refreshOverview();if(document.getElementById('section-assets').classList.contains('active'))loadAssets(document.getElementById('historySearch').value);});

document.getElementById('exportLocalHistoryBtn').addEventListener('click',()=>{
    const data=getLocalHistory();
    if(!data.length){showToast('No local history to export.','error');return;}
    const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');a.href=url;a.download=`emergens-local-history-${Date.now()}.json`;document.body.appendChild(a);a.click();a.remove();
    URL.revokeObjectURL(url);
    showToast('Local history exported.');
});
document.getElementById('clearLocalHistoryBtn').addEventListener('click',()=>{
    if(!getLocalHistory().length){showToast('Local history is already empty.','error');return;}
    if(!confirm('Clear all locally stored scan history? This cannot be undone.'))return;
    setLocalHistory([]);
    showToast('Local history cleared.');
    if(getStoragePref()==='local'){refreshOverview();if(document.getElementById('section-assets').classList.contains('active'))loadAssets(document.getElementById('historySearch').value);}
});

document.getElementById('langPillEn').addEventListener('click',()=>setLanguage('en'));
document.getElementById('langPillMs').addEventListener('click',()=>setLanguage('ms'));

// ─── SECTION CHANGE HANDLER ────────────────────────────────
window.addEventListener('section-change',e=>{
    if(e.detail==='assets')loadAssets(document.getElementById('historySearch').value);
    if(e.detail==='console')refreshConsole();
    if(e.detail==='settings')conditionalLoadUsers();
    if(e.detail==='api'){loadApiKeys();renderRecentKeys();}
    if(e.detail==='chat')renderChatWindow();
    if(e.detail==='telegram'){if(telegramConnected)checkTelegramStatus();renderTelegramSteps();}
    if(e.detail==='schools'){ if(schoolData.length===0) loadSchoolData(); }
    if(e.detail==='preferences'){initStorageChoice();initLangUI();}
});

// ─── RESUME SCAN + INIT ────────────────────────────────────
function resumeScanIfAny(){
    if(activeScanJobId&&activeScanStart){
        const target=localStorage.getItem('oxsActiveScanTarget')||'unknown';
        const mode=localStorage.getItem('oxsActiveScanMode')||'basic';
        resetProgressUI();
        pollScan(activeScanJobId,target,false,mode);
    }
}

applyLanguage();
initStorageChoice();
renderTelegramSteps();

setTimeout(()=>{
    applyRoleRestrictions();
    resumeScanIfAny();
    loadApiKeys();
    renderRecentKeys();
    initTelegram();
},400);

// ╔══════════════════════════════════════════════════════════╗
// ║  FLOATING WINDOW MANAGER — draggable, resizable popups     ║
// ╚══════════════════════════════════════════════════════════╝
(function(){
    const root=document.getElementById('floatingWindowsRoot');
    const openWindows={}; // id -> element
    let zCounter=10;
    let cascadeIndex=0;

    function clamp(v,min,max){return Math.max(min,Math.min(max,v));}

    function bringToFront(win){
        zCounter+=1;
        win.style.zIndex=zCounter;
    }

    function loadGeometry(id,defaults){
        try{
            const saved=JSON.parse(localStorage.getItem('emergens-fw-'+id));
            if(saved && typeof saved.x==='number')return saved;
        }catch(e){}
        return null;
    }
    function saveGeometry(id,win){
        try{
            localStorage.setItem('emergens-fw-'+id, JSON.stringify({
                x: parseInt(win.style.left,10)||0,
                y: parseInt(win.style.top,10)||0,
                w: win.offsetWidth,
                h: win.offsetHeight
            }));
        }catch(e){}
    }

    window.openFloatingWindow=function(id,opts){
        // opts: { title, icon, iconClass, width, height, minWidth, minHeight, buildBody(bodyEl) }
        if(openWindows[id]){
            if(openWindows[id].classList.contains('fw-minimized')){
                restoreFloatingWindow(id);
            }
            bringToFront(openWindows[id]);
            return openWindows[id];
        }
        const width=opts.width||340, height=opts.height||420;
        const minWidth=opts.minWidth||260, minHeight=opts.minHeight||200;
        const saved=loadGeometry(id);
        cascadeIndex=(cascadeIndex+1)%6;
        const defaultX=window.innerWidth-width-40-(cascadeIndex*18);
        const defaultY=90+(cascadeIndex*18);

        const win=document.createElement('div');
        win.className='fw-window';
        win.dataset.fwId=id;
        win.dataset.fwTitle=opts.title||'Window';
        win.dataset.fwIcon=opts.icon||'fas fa-window-restore';
        win.style.width=(saved&&saved.w?saved.w:width)+'px';
        win.style.height=(saved&&saved.h?saved.h:height)+'px';
        win.style.left=clamp(saved?saved.x:defaultX,8,window.innerWidth-100)+'px';
        win.style.top=clamp(saved?saved.y:defaultY,8,window.innerHeight-100)+'px';

        win.innerHTML=`
            <div class="fw-header">
                <div class="fw-header-icon ${opts.iconClass||''}"><i class="${opts.icon||'fas fa-window-restore'}"></i></div>
                <div class="fw-header-title">${escapeHtml(opts.title||'Window')}</div>
                <div class="fw-header-actions">
                    <button class="fw-header-btn fw-minimize" title="Minimize"><i class="fas fa-minus"></i></button>
                    <button class="fw-header-btn fw-close" title="Close"><i class="fas fa-xmark"></i></button>
                </div>
            </div>
            <div class="fw-body"></div>
            <div class="fw-resize-handle"></div>
        `;
        root.appendChild(win);
        openWindows[id]=win;
        bringToFront(win);

        const body=win.querySelector('.fw-body');
        if(typeof opts.buildBody==='function')opts.buildBody(body,win);

        // ---- drag (header) ----
        const header=win.querySelector('.fw-header');
        header.addEventListener('pointerdown',(e)=>{
            if(e.target.closest('.fw-header-btn'))return;
            bringToFront(win);
            win.classList.add('fw-dragging');
            const startX=e.clientX, startY=e.clientY;
            const startLeft=win.offsetLeft, startTop=win.offsetTop;
            header.setPointerCapture(e.pointerId);
            function onMove(ev){
                const nx=clamp(startLeft+(ev.clientX-startX),4,window.innerWidth-60);
                const ny=clamp(startTop+(ev.clientY-startY),4,window.innerHeight-40);
                win.style.left=nx+'px'; win.style.top=ny+'px';
            }
            function onUp(ev){
                header.releasePointerCapture(e.pointerId);
                header.removeEventListener('pointermove',onMove);
                header.removeEventListener('pointerup',onUp);
                win.classList.remove('fw-dragging');
                saveGeometry(id,win);
            }
            header.addEventListener('pointermove',onMove);
            header.addEventListener('pointerup',onUp);
        });
        win.addEventListener('pointerdown',()=>bringToFront(win));

        // ---- resize (corner handle) ----
        const handle=win.querySelector('.fw-resize-handle');
        handle.addEventListener('pointerdown',(e)=>{
            e.stopPropagation();
            bringToFront(win);
            const startX=e.clientX, startY=e.clientY;
            const startW=win.offsetWidth, startH=win.offsetHeight;
            handle.setPointerCapture(e.pointerId);
            function onMove(ev){
                const nw=clamp(startW+(ev.clientX-startX),minWidth,Math.min(720,window.innerWidth-40));
                const nh=clamp(startH+(ev.clientY-startY),minHeight,Math.min(760,window.innerHeight-40));
                win.style.width=nw+'px'; win.style.height=nh+'px';
            }
            function onUp(){
                handle.releasePointerCapture(e.pointerId);
                handle.removeEventListener('pointermove',onMove);
                handle.removeEventListener('pointerup',onUp);
                saveGeometry(id,win);
            }
            handle.addEventListener('pointermove',onMove);
            handle.addEventListener('pointerup',onUp);
        });

        win.querySelector('.fw-close').addEventListener('click',()=>closeFloatingWindow(id));
        win.querySelector('.fw-minimize').addEventListener('click',()=>minimizeFloatingWindow(id));

        return win;
    };

    // ---- minimize / dock ----
    const dock=document.createElement('div');
    dock.className='fw-dock';
    dock.id='fwDock';
    document.body.appendChild(dock);

    function minimizeFloatingWindow(id){
        const win=openWindows[id];
        if(!win||win.classList.contains('fw-minimized'))return;
        win.classList.add('fw-minimized');
        const item=document.createElement('div');
        item.className='fw-dock-item';
        item.dataset.dockFor=id;
        item.innerHTML=`<div class="fw-dock-icon"><i class="${win.dataset.fwIcon}"></i></div><div class="fw-dock-title">${escapeHtml(win.dataset.fwTitle)}</div>`;
        item.addEventListener('click',()=>{ restoreFloatingWindow(id); bringToFront(win); });
        dock.appendChild(item);
    }
    window.minimizeFloatingWindow=minimizeFloatingWindow;

    function restoreFloatingWindow(id){
        const win=openWindows[id];
        if(!win)return;
        win.classList.remove('fw-minimized');
        const item=dock.querySelector(`[data-dock-for="${id}"]`);
        if(item)item.remove();
    }
    window.restoreFloatingWindow=restoreFloatingWindow;

    window.closeFloatingWindow=function(id){
        const win=openWindows[id];
        if(!win)return;
        const item=dock.querySelector(`[data-dock-for="${id}"]`);
        if(item)item.remove();
        win.classList.add('fw-closing');
        setTimeout(()=>{ win.remove(); delete openWindows[id]; }, 180);
    };

    window.isFloatingWindowOpen=function(id){ return !!openWindows[id]; };
    window.getFloatingWindowBody=function(id){ return openWindows[id]?openWindows[id].querySelector('.fw-body'):null; };
})();

// ---- content builders for each Quick Menu popup ----
function buildAiChatPopup(body){
    body.innerHTML=`<div class="fw-chat"><div class="fw-chat-messages" id="fwChatMessages"></div><div class="fw-chat-input-row"><textarea id="fwChatInput" rows="1" placeholder="Ask something..."></textarea><button id="fwChatSendBtn"><i class="fas fa-paper-plane"></i></button></div></div>`;
    const msgs=body.querySelector('#fwChatMessages');
    getChatHistory().forEach(m=>addChatBubble(msgs,m.role,m.content));
    msgs.scrollTop=msgs.scrollHeight;
    const input=body.querySelector('#fwChatInput');
    const sendBtn=body.querySelector('#fwChatSendBtn');
    function send(){
        const t=input.value.trim();
        if(!t)return;
        sendChatMessage(t,msgs,input,sendBtn);
    }
    sendBtn.addEventListener('click',send);
    input.addEventListener('keydown',(e)=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();}});
}

function buildTelegramPopup(body){
    body.innerHTML=`<div class="fw-panel" id="fwTelegramPanel"></div>`;
    renderTelegramPopupContent(body.querySelector('#fwTelegramPanel'));
}
function renderTelegramPopupContent(panel){
    if(!panel)return;
    if(!telegramConnected){
        panel.innerHTML=`<div class="empty-state" style="padding:14px 6px;">${emptyCrest}<strong>Not connected</strong><span class="hint">Open the Telegram Bot section to connect a bot.</span></div><div class="fw-view-all" data-goto="telegram">Open Telegram Section</div>`;
    }else{
        const d=lastTelegramSnapshot||{};
        const chats=(d.chat_ids||[]).slice(0,5);
        panel.innerHTML=`
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                <div style="width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#4a7de0,#3560c2);display:flex;align-items:center;justify-content:center;color:#fff;flex-shrink:0;"><i class="fab fa-telegram-plane"></i></div>
                <div style="min-width:0;"><div style="font-weight:700;color:var(--text-primary);font-size:0.86rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(d.username||'@bot')}</div><div style="font-size:0.68rem;color:var(--green);"><span class="live-dot" style="display:inline-block;width:6px;height:6px;margin-right:4px;"></span>Connected</div></div>
            </div>
            <div class="fw-telegram-stat-grid">
                <div class="fw-telegram-stat"><strong>${(d.chat_ids||[]).length}</strong><span>Chats</span></div>
                <div class="fw-telegram-stat"><strong>${d.messages_today||0}</strong><span>Msgs Today</span></div>
            </div>
            <div class="fw-mini-list">
                ${chats.length?chats.map(id=>`<div class="fw-mini-row"><i class="fas fa-user" style="color:var(--steel);"></i><code style="flex:1;">${escapeHtml(String(id))}</code>${String(id)===String(d.owner_id)?'<span class="badge" style="color:var(--gold-light);">Owner</span>':''}</div>`).join(''):'<div class="empty-state" style="padding:10px;font-size:0.72rem;">No chats yet.</div>'}
            </div>
            <div class="fw-view-all" data-goto="telegram">Manage Bot</div>
        `;
    }
    panel.querySelectorAll('[data-goto]').forEach(b=>b.addEventListener('click',()=>{
        document.querySelector(`.nav-item[data-section="${b.dataset.goto}"]`).click();
        closeFloatingWindow('telegram');
    }));
}
function updateTelegramPopup(){
    const body=window.getFloatingWindowBody&&window.getFloatingWindowBody('telegram');
    if(body)renderTelegramPopupContent(body.querySelector('#fwTelegramPanel'));
}

function buildHistoryPopup(body){
    body.innerHTML=`<div class="fw-panel" id="fwHistoryPanel"></div>`;
    renderHistoryPopupContent(body.querySelector('#fwHistoryPanel'));
}
async function renderHistoryPopupContent(panel){
    if(!panel)return;
    let arr;
    if(getStoragePref()==='local'){arr=getLocalHistory();}
    else{try{const r=await fetch('/api/history');arr=await r.json();}catch(e){arr=[];}}
    const recent=(arr||[]).slice(0,6);
    if(!recent.length){
        panel.innerHTML=`<div class="empty-state" style="padding:14px 6px;">${emptyCrest}<strong>No scans yet</strong><span class="hint">Run a scan to see it here.</span></div>`;
    }else{
        panel.innerHTML=`<div class="fw-mini-list">${recent.map(r=>`<div class="fw-mini-row"><span class="badge success" style="flex-shrink:0;">${r.mode||'basic'}</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-primary);font-weight:600;">${escapeHtml(r.target)}</span></div>`).join('')}</div><div class="fw-view-all" data-goto="history">View Full History</div>`;
    }
    panel.querySelectorAll('[data-goto]').forEach(b=>b.addEventListener('click',()=>{
        document.querySelector(`.nav-item[data-section="${b.dataset.goto}"]`).click();
        closeFloatingWindow('history');
    }));
}

function buildConsolePopup(body){
    body.innerHTML=`<div class="fw-console-log" id="fwConsoleLog"></div>`;
    refreshConsole();
}

function buildScanPopup(body,mode){
    body.innerHTML=`
        <div class="fw-panel">
            <div class="fw-scan-form" id="fwScanForm-${mode}">
                <input type="text" id="fwScanTarget-${mode}" placeholder="target.com">
                <button class="btn-primary" id="fwScanStart-${mode}" style="width:100%;"><i class="fas fa-play"></i> Start ${mode==='expert'?'Expert':'Basic'} Scan</button>
                <div id="fwScanStatus-${mode}" style="font-size:0.72rem;color:var(--text-muted);text-align:center;"></div>
            </div>
        </div>
    `;
    body.querySelector(`#fwScanStart-${mode}`).addEventListener('click',async()=>{
        const input=body.querySelector(`#fwScanTarget-${mode}`);
        const target=input.value.trim();
        const statusEl=body.querySelector(`#fwScanStatus-${mode}`);
        if(!target){statusEl.textContent='Enter a target domain.';return;}
        const btn=body.querySelector(`#fwScanStart-${mode}`);
        btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner spin"></i> Starting...';
        try{
            const r=await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,mode:mode==='expert'?'expert':'basic',tools:[]})});
            const d=await r.json();
            if(d.error){statusEl.textContent=d.error;btn.disabled=false;btn.innerHTML=`<i class="fas fa-play"></i> Start ${mode==='expert'?'Expert':'Basic'} Scan`;return;}
            persistScanJob(d.job_id,target,mode==='expert'?'expert':'basic');
            resetProgressUI();
            pollScan(d.job_id,target,true,mode==='expert'?'expert':'basic');
            renderScanPopupProgress(body,mode);
            showToast(`Scan started for ${target}`);
        }catch(e){statusEl.textContent='Could not start scan.';btn.disabled=false;btn.innerHTML=`<i class="fas fa-play"></i> Start ${mode==='expert'?'Expert':'Basic'} Scan`;}
    });
}
function renderScanPopupProgress(body,mode){
    body.innerHTML=`
        <div class="fw-panel">
            <div class="scan-progress-card is-active" id="fwScanCard-${mode}" style="padding:12px;">
                <div class="scan-progress-header" style="margin-bottom:8px;">
                    <div class="scan-radar" style="width:22px;height:22px;"></div>
                    <div class="scan-progress-status"><div class="label" id="fwScanLabel-${mode}" style="font-size:0.76rem;">Initializing...</div></div>
                    <div class="scan-progress-pct" id="fwScanPct-${mode}" style="font-size:0.95rem;">0%</div>
                </div>
                <div class="scan-progress-track"><div class="fill" id="fwScanFill-${mode}"></div></div>
            </div>
        </div>
    `;
}
function updateScanPopupProgress(pct,label){
    ['basic','expert'].forEach(mode=>{
        const fill=document.getElementById(`fwScanFill-${mode}`);
        if(!fill)return;
        fill.style.width=pct+'%';
        const pctEl=document.getElementById(`fwScanPct-${mode}`);if(pctEl)pctEl.textContent=pct+'%';
        const labelEl=document.getElementById(`fwScanLabel-${mode}`);if(labelEl)labelEl.textContent=label||'Processing';
    });
}
function finishScanPopup(success,target,error){
    ['basic','expert'].forEach(mode=>{
        const card=document.getElementById(`fwScanCard-${mode}`);
        if(!card)return;
        card.classList.remove('is-active');
        card.classList.add(success?'is-complete':'is-failed');
        const labelEl=document.getElementById(`fwScanLabel-${mode}`);
        if(labelEl)labelEl.textContent=success?`Done — ${target}`:`Failed — ${error||'error'}`;
        const parent=card.closest('.fw-panel');
        if(parent&&success){
            const viewBtn=document.createElement('div');
            viewBtn.className='fw-view-all';
            viewBtn.textContent='View Results';
            viewBtn.style.marginTop='10px';
            viewBtn.addEventListener('click',()=>{
                document.querySelector('.nav-item[data-section="testing"]').click();
                closeFloatingWindow(mode==='expert'?'scan-expert':'scan-basic');
            });
            parent.appendChild(viewBtn);
        }
    });
}

// ╔══════════════════════════════════════════════════════════╗
// ║  CUSTOM QUICK LINKS ("+" button) — saved on this browser    ║
// ╚══════════════════════════════════════════════════════════╝
const CUSTOM_LINKS_KEY='emergens-quickmenu-links';
const MAX_CUSTOM_LINKS=5;
function getCustomLinks(){try{return JSON.parse(localStorage.getItem(CUSTOM_LINKS_KEY)||'[]');}catch(e){return[];}}
function setCustomLinks(arr){try{localStorage.setItem(CUSTOM_LINKS_KEY,JSON.stringify(arr));}catch(e){}}
function deriveLinkLabel(url){
    try{
        const u=new URL(url);
        return u.hostname.replace(/^www\./,'')||url;
    }catch(e){
        return url.length>18?url.slice(0,18)+'…':url;
    }
}
function addCustomLink(url){
    const links=getCustomLinks();
    if(links.length>=MAX_CUSTOM_LINKS){
        showToast(`Quick Menu already has ${MAX_CUSTOM_LINKS} custom links — remove one first.`,'error');
        return false;
    }
    const label=deriveLinkLabel(url);
    links.push({url,label,added_at:new Date().toISOString()});
    setCustomLinks(links);
    renderCustomQmItems();
    return true;
}
function removeCustomLink(index){
    const links=getCustomLinks();
    if(index<0||index>=links.length)return;
    const removed=links.splice(index,1)[0];
    setCustomLinks(links);
    renderCustomQmItems();
    showToast(`Removed ${removed.label} from Quick Menu.`);
}
function renderCustomQmItems(){
    const radial=document.getElementById('qmRadial');
    if(!radial)return;
    radial.querySelectorAll('.qm-custom-item').forEach(el=>el.remove());
    const links=getCustomLinks();
    const addBtn=radial.querySelector('.qm-add-item');
    links.forEach((link,i)=>{
        const el=document.createElement('button');
        el.className='qm-item qm-custom-item';
        el.title=`${link.label} (long-press to remove)`;
        el.textContent=link.label.slice(0,2).toUpperCase();
        el.addEventListener('click',()=>{
            closeQuickMenuFromOutside();
            window.open(link.url,'_blank','noopener');
        });
        let pressTimer=null;
        el.addEventListener('pointerdown',()=>{ pressTimer=setTimeout(()=>{ removeCustomLink(i); },650); });
        ['pointerup','pointerleave','pointercancel'].forEach(evt=>el.addEventListener(evt,()=>{ if(pressTimer)clearTimeout(pressTimer); }));
        radial.insertBefore(el,addBtn);
    });
    reindexQmItemDelays();
}
function reindexQmItemDelays(){
    const items=document.querySelectorAll('#qmRadial .qm-item');
    items.forEach((el,i)=>el.style.setProperty('--i',i));
}
let closeQuickMenuFromOutside=function(){}; // wired up below once the FAB controller exists

// ─── Add Link dialog ────────────────────────────────────────
function openAddLinkModal(){
    document.getElementById('addLinkUrlInput').value='';
    document.getElementById('addLinkModal').hidden=false;
    setTimeout(()=>document.getElementById('addLinkUrlInput').focus(),50);
}
function closeAddLinkModal(){document.getElementById('addLinkModal').hidden=true;}
function confirmAddLink(){
    let url=document.getElementById('addLinkUrlInput').value.trim();
    if(!url){showToast('Enter a link first.','error');return;}
    if(!url.startsWith('http://')&&!url.startsWith('https://'))url='http://'+url;
    if(addCustomLink(url)){
        showToast('Link added to Quick Menu.');
        closeAddLinkModal();
    }
}
document.getElementById('closeAddLinkModal').addEventListener('click',closeAddLinkModal);
document.getElementById('cancelAddLinkBtn').addEventListener('click',closeAddLinkModal);
document.getElementById('confirmAddLinkBtn').addEventListener('click',confirmAddLink);
document.getElementById('addLinkModal').addEventListener('click',function(e){if(e.target===this)closeAddLinkModal();});
document.getElementById('addLinkForm').addEventListener('submit',function(e){e.preventDefault();confirmAddLink();});

// ─── QUICK MENU: draggable circular FAB + radial quick-access menu ─────────
(function(){
    const fab = document.getElementById('quickMenuFab');
    const toggle = document.getElementById('qmToggle');
    if(!fab||!toggle)return;
    const POS_KEY = 'emergens-quickmenu-pos';
    let qmOpen = false, dragging = false, moved = false;
    let startX=0, startY=0, startRight=0, startBottom=0;

    function clamp(v,min,max){ return Math.max(min, Math.min(max, v)); }

    function loadPos(){
        try{
            const saved = JSON.parse(localStorage.getItem(POS_KEY));
            if(saved && typeof saved.right==='number' && typeof saved.bottom==='number'){
                const rect = fab.getBoundingClientRect();
                fab.style.right = clamp(saved.right, 8, window.innerWidth - rect.width - 8) + 'px';
                fab.style.bottom = clamp(saved.bottom, 8, window.innerHeight - rect.height - 8) + 'px';
            }
        }catch(e){}
    }
    function savePos(){
        const rect = fab.getBoundingClientRect();
        const right = window.innerWidth - rect.right;
        const bottom = window.innerHeight - rect.bottom;
        try{ localStorage.setItem(POS_KEY, JSON.stringify({right,bottom})); }catch(e){}
    }

    // Position the radial items along whichever ~200° arc has the most open screen
    // space, so the menu never opens off-screen no matter where the FAB has been
    // dragged, and no matter how many custom links have been added.
    function positionItems(){
        const items = document.querySelectorAll('#qmRadial .qm-item');
        const rect = toggle.getBoundingClientRect();
        const cx = rect.left + rect.width/2, cy = rect.top + rect.height/2;
        const spaceUp = cy, spaceDown = window.innerHeight-cy, spaceLeft = cx, spaceRight = window.innerWidth-cx;
        const wantsLeft = spaceLeft >= spaceRight, wantsUp = spaceUp >= spaceDown;
        const centerAngle = wantsUp ? (wantsLeft?135:45) : (wantsLeft?225:315);
        const n = items.length;
        const spread = Math.min(260, 150 + n*10);
        const startAngle = centerAngle - spread/2;
        const radius = (window.innerWidth < 480 ? 84 : 104) + Math.max(0,n-7)*6;
        items.forEach((item,i)=>{
            const deg = n>1 ? startAngle + (spread/(n-1))*i : centerAngle;
            const rad = deg*Math.PI/180;
            item.style.setProperty('--tx', (Math.cos(rad)*radius).toFixed(1)+'px');
            item.style.setProperty('--ty', (-Math.sin(rad)*radius).toFixed(1)+'px');
        });
    }

    function openMenu(){ if(qmOpen)return; qmOpen=true; positionItems(); fab.classList.add('qm-open'); toggle.setAttribute('aria-expanded','true'); }
    function closeMenu(){ if(!qmOpen)return; qmOpen=false; fab.classList.remove('qm-open'); toggle.setAttribute('aria-expanded','false'); }
    function toggleMenu(){ qmOpen ? closeMenu() : openMenu(); }
    closeQuickMenuFromOutside=closeMenu;

    toggle.addEventListener('pointerdown',(e)=>{
        dragging=true; moved=false;
        startX=e.clientX; startY=e.clientY;
        const rect=fab.getBoundingClientRect();
        startRight = window.innerWidth-rect.right; startBottom = window.innerHeight-rect.bottom;
        try{toggle.setPointerCapture(e.pointerId);}catch(err){}
        fab.classList.add('qm-dragging');
    });
    toggle.addEventListener('pointermove',(e)=>{
        if(!dragging)return;
        const dx=e.clientX-startX, dy=e.clientY-startY;
        if(Math.abs(dx)>5||Math.abs(dy)>5)moved=true;
        if(!moved)return;
        const rect=fab.getBoundingClientRect();
        const newRight = clamp(startRight-dx, 8, window.innerWidth-rect.width-8);
        const newBottom = clamp(startBottom-dy, 8, window.innerHeight-rect.height-8);
        fab.style.right = newRight+'px'; fab.style.bottom = newBottom+'px';
        if(qmOpen) positionItems(); // radial items always stay attached to the button while dragging
    });
    function endDrag(e){
        if(!dragging)return;
        dragging=false;
        fab.classList.remove('qm-dragging');
        try{toggle.releasePointerCapture(e.pointerId);}catch(err){}
        if(moved){ savePos(); } else { toggleMenu(); }
    }
    toggle.addEventListener('pointerup', endDrag);
    toggle.addEventListener('pointercancel', endDrag);

    document.addEventListener('click',(e)=>{ if(qmOpen && !fab.contains(e.target) && !e.target.closest('#addLinkModal')) closeMenu(); });
    document.addEventListener('keydown',(e)=>{ if(e.key==='Escape' && qmOpen) closeMenu(); });
    window.addEventListener('resize',()=>{ if(qmOpen) positionItems(); loadPos(); });

    function qmGoToSection(sec){
        const btn=document.querySelector(`.nav-item[data-section="${sec}"]`);
        if(btn)btn.click();
        closeMenu();
    }

    // Built-in items now open floating popups instead of just navigating away,
    // so the person never has to leave whatever they were looking at.
    document.querySelectorAll('#qmRadial .qm-item[data-qm-action]').forEach(btn=>{
        const action = btn.dataset.qmAction;
        btn.addEventListener('click',()=>{
            closeMenu();
            switch(action){
                case 'scan-basic':
                    openFloatingWindow('scan-basic',{title:'Basic Scan',icon:'fas fa-bolt',width:300,height:170,minHeight:150,buildBody:(b)=>buildScanPopup(b,'basic')});
                    break;
                case 'scan-expert':
                    openFloatingWindow('scan-expert',{title:'Expert Scan',icon:'fas fa-shield-halved',width:300,height:170,minHeight:150,buildBody:(b)=>buildScanPopup(b,'expert')});
                    break;
                case 'history':
                    openFloatingWindow('history',{title:'Recent Scans',icon:'fas fa-clock-rotate-left',width:320,height:320,buildBody:buildHistoryPopup});
                    break;
                case 'console':
                    openFloatingWindow('console',{title:'System Console',icon:'fas fa-terminal',width:380,height:320,buildBody:buildConsolePopup});
                    break;
                case 'chat':
                    openFloatingWindow('chat',{title:'AI Assistant',icon:'fas fa-robot',iconClass:'violet',width:340,height:440,minHeight:280,buildBody:buildAiChatPopup});
                    break;
                case 'telegram':
                    openFloatingWindow('telegram',{title:'Telegram Bot',icon:'fab fa-telegram-plane',iconClass:'telegram',width:300,height:340,buildBody:buildTelegramPopup});
                    break;
                case 'add-link':
                    openAddLinkModal();
                    break;
            }
        });
    });

    renderCustomQmItems();
    loadPos();
})();

// ╔══════════════════════════════════════════════════════════╗
// ║  MOBILE / TOUCH DEVICE DETECTION                            ║
// ╚══════════════════════════════════════════════════════════╝
(function(){
    const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
    const isSmallScreen = window.matchMedia('(max-width: 900px)').matches;
    if (isTouch || isSmallScreen) document.body.classList.add('is-touch-device');
})();

// ╔══════════════════════════════════════════════════════════╗
// ║  THEME STUDIO — custom colors, presets, brand, logo          ║
// ║  (owner-only, floating window)                              ║
// ╚══════════════════════════════════════════════════════════╝
const THEME_CONFIG_KEY='emergens-custom-theme';
const CUSTOM_LOGO_KEY='emergens-custom-logo';
const AUTO_CONSOLE_KEY='emergens-auto-console';
const AI_PROVIDER_KEY='emergens-ai-provider';
const CUSTOM_TITLE_KEY='emergens-custom-title';

// Cache the original crest markup + favicon once, at load time, so a custom
// logo can always be removed again and the original bolt mark restored.
let ORIGINAL_CRESTS = null;
let ORIGINAL_FAVICON = null;
function cacheOriginalBranding(){
    if (ORIGINAL_CRESTS) return;
    ORIGINAL_CRESTS = Array.from(document.querySelectorAll('.crest')).map(el => el.outerHTML);
    const favEl = document.querySelector('link[rel="icon"]');
    ORIGINAL_FAVICON = favEl ? favEl.href : null;
}

function hexToRgb(hex){
    hex = String(hex||'#3b82f6').replace('#','');
    if (hex.length === 3) hex = hex.split('').map(c=>c+c).join('');
    const num = parseInt(hex,16) || 0;
    return { r:(num>>16)&255, g:(num>>8)&255, b:num&255 };
}
function rgbToHex(r,g,b){
    return '#'+[r,g,b].map(v=>Math.max(0,Math.min(255,Math.round(v))).toString(16).padStart(2,'0')).join('');
}
function shadeColor(hex, pct){
    const {r,g,b} = hexToRgb(hex);
    const target = pct < 0 ? 0 : 255;
    const p = Math.abs(pct);
    return rgbToHex(r+(target-r)*p, g+(target-g)*p, b+(target-b)*p);
}
function readableOnColor(hex){
    const {r,g,b} = hexToRgb(hex);
    const luminance = (0.299*r + 0.587*g + 0.114*b) / 255;
    return luminance > 0.58 ? '#0d0d0d' : '#ffffff';
}

function applyPrimaryAccent(hex){
    const root=document.documentElement;
    root.style.setProperty('--red-400', shadeColor(hex, 0.34));
    root.style.setProperty('--red-500', hex);
    root.style.setProperty('--red-600', shadeColor(hex, -0.16));
    root.style.setProperty('--red-700', shadeColor(hex, -0.32));
    root.style.setProperty('--red-800', shadeColor(hex, -0.48));
    const {r,g,b} = hexToRgb(shadeColor(hex, 0.34));
    root.style.setProperty('--red-glow', `rgba(${r},${g},${b},0.35)`);
    root.style.setProperty('--red-glow-soft', `rgba(${r},${g},${b},0.12)`);
    root.style.setProperty('--on-accent', readableOnColor(shadeColor(hex, 0.34)));
    root.style.setProperty('--green', shadeColor(hex, 0.5));
    const gg = hexToRgb(shadeColor(hex, 0.5));
    root.style.setProperty('--green-glow', `rgba(${gg.r},${gg.g},${gg.b},0.18)`);
}
function applySecondaryAccent(hex){
    const root=document.documentElement;
    root.style.setProperty('--gold', hex);
    root.style.setProperty('--gold-light', shadeColor(hex, 0.3));
    const {r,g,b} = hexToRgb(hex);
    root.style.setProperty('--gold-glow', `rgba(${r},${g},${b},0.2)`);
}
function applyBrandName(name){
    if(!name)return;
    document.querySelectorAll('.brand-name').forEach(el=>el.textContent=name);
    const customTitle=loadCustomTitle();
    document.title = customTitle || `${name} — Field Intelligence Console`;
}
function loadCustomTitle(){ return localStorage.getItem(CUSTOM_TITLE_KEY)||''; }
function saveCustomTitle(t){ try{ if(t)localStorage.setItem(CUSTOM_TITLE_KEY,t); else localStorage.removeItem(CUSTOM_TITLE_KEY); }catch(e){} }
function applyCustomTitle(t){ document.title = t || `${getCurrentBrandName()} — Field Intelligence Console`; }

const THEME_PRESETS = {
    emergens: { name:'Emergens', primary:'#3b82f6', secondary:'#d4a574', brand:'EMERGENS' },
    oxysintx: { name:'Oxysintx', primary:'#c62a3e', secondary:'#c9a06a', brand:'OXYSINTX' },
    ruby:     { name:'Ruby',     primary:'#e11d48', secondary:'#fb7185', brand:null }
};

function saveThemeConfig(cfg){ try{ localStorage.setItem(THEME_CONFIG_KEY, JSON.stringify(cfg)); }catch(e){} }
function loadThemeConfig(){ try{ return JSON.parse(localStorage.getItem(THEME_CONFIG_KEY)) || null; }catch(e){ return null; } }
function applyThemeConfig(cfg){
    if(!cfg)return;
    if(cfg.primary) applyPrimaryAccent(cfg.primary);
    if(cfg.secondary) applySecondaryAccent(cfg.secondary);
    if(cfg.brand) applyBrandName(cfg.brand);
}
function applyPreset(key){
    const preset = THEME_PRESETS[key];
    if(!preset)return;
    const cfg = { preset:key, primary:preset.primary, secondary:preset.secondary, brand:preset.brand||getCurrentBrandName() };
    applyThemeConfig(cfg);
    saveThemeConfig(cfg);
    return cfg;
}
function getCurrentBrandName(){
    const el=document.querySelector('.brand-name');
    return el ? el.textContent.trim() : 'EMERGENS';
}

function saveCustomLogo(dataUrl){ try{ localStorage.setItem(CUSTOM_LOGO_KEY, dataUrl); return true; }catch(e){ return false; } }
function loadCustomLogo(){ return localStorage.getItem(CUSTOM_LOGO_KEY); }
function clearCustomLogo(){ localStorage.removeItem(CUSTOM_LOGO_KEY); }
function applyCustomLogo(dataUrl){
    cacheOriginalBranding();
    document.querySelectorAll('.crest').forEach(el=>{
        const img=document.createElement('img');
        img.src=dataUrl;
        img.className=el.className+' crest-custom-img';
        img.alt='Logo';
        el.replaceWith(img);
    });
    const favEl=document.querySelector('link[rel="icon"]');
    if(favEl)favEl.href=dataUrl;
}
function restoreOriginalLogo(){
    cacheOriginalBranding();
    if(!ORIGINAL_CRESTS)return;
    document.querySelectorAll('.crest-custom-img').forEach((img,i)=>{
        if(ORIGINAL_CRESTS[i]){
            const temp=document.createElement('div');
            temp.innerHTML=ORIGINAL_CRESTS[i];
            img.replaceWith(temp.firstElementChild);
        }
    });
    const favEl=document.querySelector('link[rel="icon"]');
    if(favEl && ORIGINAL_FAVICON)favEl.href=ORIGINAL_FAVICON;
}

function getAutoConsolePref(){ return localStorage.getItem(AUTO_CONSOLE_KEY)==='true'; }
function setAutoConsolePref(v){ localStorage.setItem(AUTO_CONSOLE_KEY, v?'true':'false'); }

function getAiProviderConfig(){
    try{ return JSON.parse(localStorage.getItem(AI_PROVIDER_KEY)) || null; }catch(e){ return null; }
}
function setAiProviderConfig(cfg){ try{ localStorage.setItem(AI_PROVIDER_KEY, JSON.stringify(cfg)); }catch(e){} }
function clearAiProviderConfig(){ localStorage.removeItem(AI_PROVIDER_KEY); }

function initThemeOnLoad(){
    cacheOriginalBranding();
    const cfg=loadThemeConfig();
    if(cfg)applyThemeConfig(cfg);
    const logo=loadCustomLogo();
    if(logo)applyCustomLogo(logo);
    applyCustomTitle(loadCustomTitle());
}
initThemeOnLoad();

function buildThemeStudioPopup(body){
    const cfg=loadThemeConfig()||{};
    const currentPrimary=cfg.primary||'#3b82f6';
    const currentSecondary=cfg.secondary||'#8b5cf6';
    const activePreset=cfg.preset||'';
    const aiCfg=getAiProviderConfig();
    body.innerHTML=`
        <div class="fw-panel" style="padding:16px;">
            <div class="ts-section">
                <div class="ts-section-title"><i class="fas fa-swatchbook"></i> Theme Presets</div>
                <div class="ts-preset-grid" id="tsPresetGrid">
                    <div class="ts-preset ${activePreset==='emergens'?'active':''}" data-preset="emergens"><div class="ts-preset-swatch" style="background:linear-gradient(135deg,#3b82f6,#8b5cf6);"></div><div class="ts-preset-name">Emergens</div></div>
                    <div class="ts-preset ${activePreset==='oxysintx'?'active':''}" data-preset="oxysintx"><div class="ts-preset-swatch" style="background:linear-gradient(135deg,#c62a3e,#c9a06a);"></div><div class="ts-preset-name">Oxysintx</div></div>
                    <div class="ts-preset ${activePreset==='ruby'?'active':''}" data-preset="ruby"><div class="ts-preset-swatch" style="background:linear-gradient(135deg,#e11d48,#fb7185);"></div><div class="ts-preset-name">Ruby</div></div>
                </div>
            </div>
            <div class="ts-section">
                <div class="ts-section-title"><i class="fas fa-eye-dropper"></i> Custom Colors</div>
                <div class="ts-color-row"><label>Primary accent</label><input type="color" id="tsPrimaryColor" value="${currentPrimary}"></div>
                <div class="ts-color-row"><label>Secondary accent</label><input type="color" id="tsSecondaryColor" value="${currentSecondary}"></div>
                <div class="ts-btn-row"><button class="btn-primary" id="tsApplyColors" style="padding:9px;"><i class="fas fa-check"></i> Apply Colors</button></div>
            </div>
            <div class="ts-section">
                <div class="ts-section-title"><i class="fas fa-signature"></i> Brand &amp; Title</div>
                <div class="ts-color-row"><label>Brand name</label></div>
                <div class="input-group" style="margin-bottom:8px;"><i class="fas fa-tag"></i><input type="text" id="tsBrandName" placeholder="EMERGENS" maxlength="24" value="${escapeHtml(getCurrentBrandName())}"></div>
                <div class="ts-color-row"><label>Custom page title</label></div>
                <div class="input-group" style="margin-bottom:8px;"><i class="fas fa-window-maximize"></i><input type="text" id="tsCustomTitle" placeholder="Shown in the browser tab" maxlength="60" value="${escapeHtml(loadCustomTitle())}"></div>
                <div class="ts-btn-row"><button class="btn-primary" id="tsSaveBrandTitle" style="padding:9px;"><i class="fas fa-check"></i> Save</button><button class="btn-secondary btn-danger" id="tsResetTitle" style="padding:9px;"><i class="fas fa-rotate-left"></i> Clear Title</button></div>
            </div>
            <div class="ts-section">
                <div class="ts-section-title"><i class="fas fa-image"></i> Custom Logo</div>
                <div class="ts-logo-upload" id="tsLogoUpload">
                    <div class="ts-logo-preview" id="tsLogoPreview">${loadCustomLogo()?`<img src="${loadCustomLogo()}">`:'<i class="fas fa-bolt" style="color:var(--red-400);font-size:1.3rem;"></i>'}</div>
                    <div style="font-size:0.74rem;color:var(--text-secondary);">Click to upload a logo (PNG/SVG, replaces the bolt mark + favicon)</div>
                </div>
                <input type="file" id="tsLogoFile" accept="image/*" style="display:none;">
                <div class="pp-or-divider">or</div>
                <div class="input-group" style="margin-bottom:8px;"><i class="fas fa-link"></i><input type="text" id="tsLogoUrl" placeholder="https://example.com/logo.png"></div>
                <div class="ts-btn-row"><button class="btn-secondary" id="tsLogoUrlApply" style="padding:9px;"><i class="fas fa-check"></i> Use This URL</button><button class="btn-secondary btn-danger" id="tsResetLogo" style="padding:9px;"><i class="fas fa-rotate-left"></i> Reset to Default</button></div>
            </div>
            <div class="ts-section">
                <div class="ts-section-title"><i class="fas fa-robot"></i> AI Provider</div>
                <p style="font-size:0.72rem;color:var(--text-muted);margin-bottom:8px;line-height:1.5;">Default uses the built-in siputzx.my.id endpoint. To use your own OpenAI-compatible endpoint instead, fill this in — it's saved only in this browser, never in the page source.</p>
                <div class="input-group" style="margin-bottom:8px;"><i class="fas fa-link"></i><input type="text" id="tsAiEndpoint" placeholder="https://your-endpoint/v1/chat/completions" value="${aiCfg&&aiCfg.endpoint?escapeHtml(aiCfg.endpoint):''}"></div>
                <div class="input-group" style="margin-bottom:8px;"><i class="fas fa-key"></i><input type="password" id="tsAiKey" placeholder="API key" value="${aiCfg&&aiCfg.key?escapeHtml(aiCfg.key):''}"></div>
                <div class="input-group" style="margin-bottom:8px;"><i class="fas fa-microchip"></i><input type="text" id="tsAiModel" placeholder="Model name" value="${aiCfg&&aiCfg.model?escapeHtml(aiCfg.model):''}"></div>
                <div class="ts-btn-row"><button class="btn-secondary" id="tsAiSave" style="padding:9px;"><i class="fas fa-save"></i> Save</button><button class="btn-secondary btn-danger" id="tsAiClear" style="padding:9px;"><i class="fas fa-broom"></i> Use Default</button></div>
            </div>
            <div class="ts-section">
                <div class="ts-section-title"><i class="fas fa-sliders"></i> Behavior</div>
                <div class="ts-toggle-row">
                    <span>Auto-show Console after scan<span class="hint">Opens the console popup the moment a scan finishes</span></span>
                    <label class="toggle-switch"><input type="checkbox" id="tsAutoConsole" ${getAutoConsolePref()?'checked':''}><span class="toggle-slider"></span></label>
                </div>
            </div>
        </div>
    `;

    body.querySelectorAll('.ts-preset').forEach(p=>p.addEventListener('click',()=>{
        applyPreset(p.dataset.preset);
        body.querySelectorAll('.ts-preset').forEach(x=>x.classList.remove('active'));
        p.classList.add('active');
        const nc=loadThemeConfig();
        body.querySelector('#tsPrimaryColor').value=nc.primary;
        body.querySelector('#tsSecondaryColor').value=nc.secondary;
        showToast(`${THEME_PRESETS[p.dataset.preset].name} theme applied.`);
    }));

    body.querySelector('#tsApplyColors').addEventListener('click',()=>{
        const primary=body.querySelector('#tsPrimaryColor').value;
        const secondary=body.querySelector('#tsSecondaryColor').value;
        const cfg={preset:'',primary,secondary,brand:getCurrentBrandName()};
        applyThemeConfig(cfg);
        saveThemeConfig(cfg);
        body.querySelectorAll('.ts-preset').forEach(x=>x.classList.remove('active'));
        showToast('Custom colors applied.');
    });

    body.querySelector('#tsSaveBrandTitle').addEventListener('click',()=>{
        const brand=body.querySelector('#tsBrandName').value.trim()||'EMERGENS';
        const title=body.querySelector('#tsCustomTitle').value.trim();
        const cfg={...(loadThemeConfig()||{}),brand};
        applyThemeConfig(cfg);
        saveThemeConfig(cfg);
        saveCustomTitle(title);
        applyCustomTitle(title);
        showToast('Brand name and title saved.');
    });
    body.querySelector('#tsResetTitle').addEventListener('click',()=>{
        body.querySelector('#tsCustomTitle').value='';
        saveCustomTitle('');
        applyCustomTitle('');
        showToast('Custom title cleared.');
    });

    const logoUpload=body.querySelector('#tsLogoUpload');
    const logoFile=body.querySelector('#tsLogoFile');
    logoUpload.addEventListener('click',()=>logoFile.click());
    logoFile.addEventListener('change',()=>{
        const file=logoFile.files[0];
        if(!file)return;
        if(file.size>800000){ showToast('Logo too large — please use an image under 800KB.','error'); return; }
        const reader=new FileReader();
        reader.onload=()=>{
            const dataUrl=reader.result;
            if(saveCustomLogo(dataUrl)){
                applyCustomLogo(dataUrl);
                body.querySelector('#tsLogoPreview').innerHTML=`<img src="${dataUrl}">`;
                showToast('Custom logo applied.');
            }else{
                showToast('Could not save logo (storage full).','error');
            }
        };
        reader.readAsDataURL(file);
    });
    body.querySelector('#tsLogoUrlApply').addEventListener('click',()=>{
        const url=body.querySelector('#tsLogoUrl').value.trim();
        if(!url){ showToast('Paste a logo image URL first.','error'); return; }
        if(saveCustomLogo(url)){
            applyCustomLogo(url);
            body.querySelector('#tsLogoPreview').innerHTML=`<img src="${escapeHtml(url)}">`;
            showToast('Custom logo applied from URL.');
        }else{
            showToast('Could not save logo URL.','error');
        }
    });
    body.querySelector('#tsResetLogo').addEventListener('click',()=>{
        clearCustomLogo();
        restoreOriginalLogo();
        body.querySelector('#tsLogoPreview').innerHTML='<i class="fas fa-bolt" style="color:var(--red-400);font-size:1.3rem;"></i>';
        body.querySelector('#tsLogoUrl').value='';
        showToast('Reverted to default logo.');
    });

    body.querySelector('#tsAiSave').addEventListener('click',()=>{
        const endpoint=body.querySelector('#tsAiEndpoint').value.trim();
        const key=body.querySelector('#tsAiKey').value.trim();
        const model=body.querySelector('#tsAiModel').value.trim();
        if(!endpoint){ showToast('Enter an endpoint URL first.','error'); return; }
        setAiProviderConfig({endpoint,key,model});
        showToast('AI provider saved to this browser.');
    });
    body.querySelector('#tsAiClear').addEventListener('click',()=>{
        clearAiProviderConfig();
        body.querySelector('#tsAiEndpoint').value='';
        body.querySelector('#tsAiKey').value='';
        body.querySelector('#tsAiModel').value='';
        showToast('Reverted to the built-in AI provider.');
    });

    body.querySelector('#tsAutoConsole').addEventListener('change',function(){
        setAutoConsolePref(this.checked);
        showToast(this.checked?'Console will auto-open after each scan.':'Auto-console disabled.');
    });
}

document.getElementById('navThemeStudio').addEventListener('click',()=>{
    if(currentUserRole!=='owner'){ showToast('Theme Studio is available to Owners only.','error'); return; }
    openFloatingWindow('theme-studio',{title:'Theme Studio',icon:'fas fa-palette',iconClass:'ruby',width:340,height:560,minHeight:400,buildBody:buildThemeStudioPopup});
});

// ╔══════════════════════════════════════════════════════════╗
// ║  NOTES — simple localStorage scratchpad                     ║
// ╚══════════════════════════════════════════════════════════╝
const NOTES_KEY='emergens-notes';
function getNotesText(){ return localStorage.getItem(NOTES_KEY)||''; }
function setNotesText(v){ try{ localStorage.setItem(NOTES_KEY, v); }catch(e){} }
function buildNotesPopup(body){
    body.innerHTML=`<div class="notes-wrap"><textarea class="notes-textarea" id="notesTextarea" placeholder="Jot down anything here — saved automatically to this browser...">${escapeHtml(getNotesText())}</textarea><div class="notes-status-row"><span><i class="fas fa-hard-drive"></i> Saved locally</span><span id="notesSavedIndicator"></span></div></div>`;
    const ta=body.querySelector('#notesTextarea');
    let saveTimer=null;
    ta.addEventListener('input',()=>{
        clearTimeout(saveTimer);
        saveTimer=setTimeout(()=>{
            setNotesText(ta.value);
            const ind=body.querySelector('#notesSavedIndicator');
            if(ind){ ind.textContent='Saved ' + new Date().toLocaleTimeString(); }
        },400);
    });
}
document.getElementById('notesToggleBtn').addEventListener('click',()=>{
    openFloatingWindow('notes',{title:'Notes',icon:'fas fa-note-sticky',width:300,height:360,minHeight:220,buildBody:buildNotesPopup});
});

// ╔══════════════════════════════════════════════════════════╗
// ║  MINECRAFT SERVER STATUS — api.mcstatus.io                  ║
// ╚══════════════════════════════════════════════════════════╝
// NOTE: this was built directly from the official mcstatus.io response
// documentation, but that domain wasn't reachable from the environment
// that wrote this code, so it could not be verified against the live API.
// Every field is read defensively (optional chaining + fallbacks) so a
// slightly different real-world response still renders instead of crashing.
async function checkMinecraftStatus(address, edition){
    const base = edition === 'bedrock'
        ? `https://api.mcstatus.io/v2/status/bedrock/${encodeURIComponent(address)}`
        : `https://api.mcstatus.io/v2/status/java/${encodeURIComponent(address)}`;
    const res = await fetch(base);
    if(!res.ok) throw new Error(`mcstatus.io replied with HTTP ${res.status}`);
    return await res.json();
}
function renderMinecraftResult(data, address){
    const online = !!data.online;
    const version = data.version?.name_clean || data.version?.name_raw || '--';
    const playersOnline = data.players?.online ?? '--';
    const playersMax = data.players?.max ?? '--';
    const pct = (typeof data.players?.online === 'number' && typeof data.players?.max === 'number' && data.players.max > 0)
        ? Math.min(100, Math.round((data.players.online / data.players.max) * 100)) : 0;
    const motd = data.motd?.clean || (online ? '(no MOTD)' : '');
    const icon = data.icon || null;
    const ip = data.ip_address || data.srv_record?.host || address;
    const port = data.port || data.srv_record?.port || '--';

    return `
        <div class="mc-status-card ${online?'':'offline'}">
            <div class="mc-icon-wrap">${icon?`<img src="${icon}" alt="server icon">`:'<i class="fas fa-cube"></i>'}</div>
            <div style="flex:1;min-width:0;">
                <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px;">
                    <strong style="font-size:0.98rem;color:var(--text-primary);">${escapeHtml(data.host||address)}</strong>
                    <span class="badge ${online?'success':'danger'}"><i class="fas fa-${online?'check':'times'}"></i> ${online?'Online':'Offline'}</span>
                    ${data.eula_blocked?'<span class="badge warning"><i class="fas fa-triangle-exclamation"></i> EULA Blocked</span>':''}
                </div>
                ${online?`<div class="mc-motd">${escapeHtml(motd)}</div>` : '<div class="empty-state" style="padding:10px 0;">This server did not respond — it may be offline or the address may be wrong.</div>'}
                ${online?`
                <div class="port-summary-grid" style="margin-top:10px;">
                    <div class="port-summary-card"><div class="port-summary-value" style="color:var(--steel);font-size:1.1rem;">${escapeHtml(String(version))}</div><div class="port-summary-label">Version</div></div>
                    <div class="port-summary-card"><div class="port-summary-value" style="color:var(--green);">${playersOnline}/${playersMax}</div><div class="port-summary-label">Players</div></div>
                    <div class="port-summary-card"><div class="port-summary-value" style="color:var(--gold);font-size:1rem;">${escapeHtml(String(ip))}</div><div class="port-summary-label">IP Address</div></div>
                    <div class="port-summary-card"><div class="port-summary-value" style="color:var(--amber);">${port}</div><div class="port-summary-label">Port</div></div>
                </div>
                <div class="mc-player-bar"><div class="mc-player-bar-fill" style="width:${pct}%;"></div></div>
                ${Array.isArray(data.players?.list)&&data.players.list.length?`<div style="margin-top:10px;font-size:0.72rem;color:var(--text-muted);">Sample players: ${data.players.list.slice(0,8).map(p=>escapeHtml(p.name_clean||p.name_raw||'?')).join(', ')}</div>`:''}
                ${Array.isArray(data.mods)&&data.mods.length?`<div style="margin-top:8px;font-size:0.72rem;color:var(--text-muted);">Mods: ${data.mods.slice(0,10).map(m=>escapeHtml(m.name)).join(', ')}</div>`:''}
                `:''}
            </div>
        </div>
    `;
}
document.getElementById('mcCheckBtn').addEventListener('click', async ()=>{
    const address=document.getElementById('mcAddressInput').value.trim();
    const edition=document.getElementById('mcEdition').value;
    const resultsEl=document.getElementById('mcResults');
    if(!address){ showToast('Enter a server address.','error'); return; }
    const btn=document.getElementById('mcCheckBtn');
    const orig=btn.innerHTML;
    btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner spin"></i> Checking...';
    resultsEl.innerHTML='<div class="empty-state"><i class="fas fa-spinner spin"></i> <span>Contacting mcstatus.io...</span></div>';
    try{
        const data=await checkMinecraftStatus(address, edition);
        resultsEl.innerHTML=renderMinecraftResult(data, address);
    }catch(e){
        resultsEl.innerHTML=`<div class="empty-state"><i class="fas fa-circle-info" style="font-size:1.4rem;color:var(--text-muted);"></i><strong>Could not check that server</strong><span class="hint">${escapeHtml(e.message)}</span></div>`;
    }finally{
        btn.disabled=false; btn.innerHTML=orig;
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  NETWORK TRAFFIC — inbound / outbound request tracking        ║
// ╚══════════════════════════════════════════════════════════╝
// Outbound is real: every fetch() this dashboard itself makes is counted
// as it happens. Inbound reads from /api/system/stats defensively (several
// likely field names are tried) since that's server-side traffic this page
// cannot observe directly — if the backend doesn't provide it, it shows
// '--' honestly rather than a made-up number.
let outboundRequestLog=[];
let inboundSample=null;
const _originalFetch=window.fetch.bind(window);
window.fetch=function(...args){
    const now=Date.now();
    outboundRequestLog.push(now);
    outboundRequestLog=outboundRequestLog.filter(ts=>now-ts<60000);
    return _originalFetch(...args);
};

// Real animated history graph (replaces the old decorative pulse-bars).
// Outbound is bucketed from real fetch() timestamps this page issued.
// Inbound is sampled from whatever the backend reports each poll — if the
// backend never reports a number, we show an honest "waiting for data"
// state instead of drawing a fabricated line.
const NT_HISTORY_LEN=24;
let outboundHistory=new Array(NT_HISTORY_LEN).fill(0);
let inboundHistory=new Array(NT_HISTORY_LEN).fill(0);
let inboundTimes=new Array(NT_HISTORY_LEN).fill(null);
let inboundHasRealData=false;

function ntBuildPaths(history,width,height){
    const max=Math.max(1,...history);
    const stepX=width/(history.length-1);
    const pts=history.map((v,i)=>({x:i*stepX, y: height-2-(v/max)*(height-6)}));
    const line=pts.map((p,i)=>`${i===0?'M':'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    const area=`${line} L${width},${height} L0,${height} Z`;
    return {line,area,pts,last:pts[pts.length-1]};
}
function ntFmtStamp(ts){
    if(!ts)return '';
    const d=new Date(ts);
    const day=d.toLocaleDateString(undefined,{weekday:'short'});
    const date=d.toLocaleDateString(undefined,{day:'2-digit',month:'short'});
    const time=d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    return `${day}, ${date} · ${time}`;
}
// Delegated hover wiring — attached once per spark container; the container element
// itself survives innerHTML swaps, so the listeners keep working after each refresh.
function ntWireHover(el,unit){
    if(el.dataset.hoverWired)return;
    el.dataset.hoverWired='1';
    const tip=document.createElement('div');
    tip.className='nt-tooltip'; tip.hidden=true;
    el.appendChild(tip);
    const show=(pt)=>{
        tip.innerHTML=`<span class="ntt-v">${escapeHtml(String(pt.dataset.v))} ${escapeHtml(unit)}</span><span class="ntt-t">${escapeHtml(pt.dataset.t||'—')}</span>`;
        tip.style.left=pt.style.left; tip.style.top=pt.style.top; tip.hidden=false;
    };
    el.addEventListener('mouseover',(e)=>{ const hp=e.target.closest('.nt-hp'); if(hp)show(hp); });
    el.addEventListener('mouseout',(e)=>{ if(e.target.closest('.nt-hp'))tip.hidden=true; });
}
function renderTrafficGraph(containerId,history,hasRealData,times,unit){
    const el=document.getElementById(containerId);
    if(!el)return;
    unit=unit||'req';
    ntWireHover(el,unit);
    const tipEl=el.querySelector('.nt-tooltip');
    if(!hasRealData){ el.innerHTML=`<div class="nt-empty">Waiting for data…</div>`; if(tipEl)el.appendChild(tipEl); return; }
    const W=240,H=44;
    const {line,area,pts,last}=ntBuildPaths(history,W,H);
    const hotspots=pts.map((p,i)=>{
        const leftPct=(p.x/W)*100, topPct=(p.y/H)*100;
        return `<span class="nt-hp" style="left:${leftPct.toFixed(2)}%;top:${topPct.toFixed(2)}%" data-v="${history[i]}" data-t="${escapeHtml(ntFmtStamp(times&&times[i]))}"></span>`;
    }).join('');
    el.innerHTML=`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
        <line class="nt-grid-line" x1="0" y1="${H-1}" x2="${W}" y2="${H-1}"></line>
        <path class="nt-area" d="${area}"></path>
        <path class="nt-line" d="${line}"></path>
        <circle class="nt-dot" cx="${last.x.toFixed(1)}" cy="${last.y.toFixed(1)}"></circle>
    </svg><div class="nt-hoverlayer">${hotspots}</div>`;
    if(tipEl)el.appendChild(tipEl);
}
async function refreshNetworkTraffic(){
    // Outbound: bucket real fetch() timestamps into a 60s window.
    const now=Date.now(), windowMs=60000, bucketMs=windowMs/NT_HISTORY_LEN;
    const buckets=new Array(NT_HISTORY_LEN).fill(0);
    outboundRequestLog.forEach(ts=>{
        const age=now-ts;
        if(age<0||age>windowMs)return;
        const idx=Math.min(NT_HISTORY_LEN-1,Math.floor(age/bucketMs));
        buckets[NT_HISTORY_LEN-1-idx]++;
    });
    outboundHistory=buckets;
    // Each bucket spans bucketMs; bucket i is centred at now - (LEN-1-i)*bucketMs.
    const outboundTimes=buckets.map((_,i)=>now-(NT_HISTORY_LEN-1-i)*bucketMs);
    renderTrafficGraph('netOutboundSpark', outboundHistory, true, outboundTimes, 'req');

    const outEl=document.getElementById('netOutboundValue'), outSubEl=document.getElementById('netOutboundSub');
    if(outEl){
        outEl.textContent=outboundRequestLog.length;
        outSubEl.textContent=`${outboundRequestLog.length} req/min`;
    }
    const inEl=document.getElementById('netInboundValue'), inSubEl=document.getElementById('netInboundSub');
    if(!inEl)return;
    try{
        const r=await fetch('/api/system/stats');
        const s=await r.json();
        const inbound = s.network_in ?? s.inbound_requests ?? s.requests_in ?? s.rx_requests ?? s.inbound ?? null;
        const inboundRate = s.network_in_rate ?? s.inbound_rate ?? null;
        if(inbound!==null){
            inEl.textContent = typeof inbound==='number' ? inbound.toLocaleString() : String(inbound);
            inSubEl.textContent = inboundRate!==null ? `${inboundRate} req/min` : 'from server stats';
            inboundHasRealData=true;
            inboundHistory=inboundHistory.slice(1).concat([Number(inbound)||0]);
            inboundTimes=inboundTimes.slice(1).concat([Date.now()]);
            renderTrafficGraph('netInboundSpark', inboundHistory, true, inboundTimes, 'req');
        }else{
            inEl.textContent='--';
            inSubEl.textContent='not reported by server';
            renderTrafficGraph('netInboundSpark', inboundHistory, inboundHasRealData, inboundTimes, 'req');
        }
    }catch(e){
        inEl.textContent='--';
        inSubEl.textContent='unavailable';
        renderTrafficGraph('netInboundSpark', inboundHistory, inboundHasRealData, inboundTimes, 'req');
    }
}
refreshNetworkTraffic();
setInterval(()=>{ if(document.getElementById('section-overview').classList.contains('active')) refreshNetworkTraffic(); }, 8000);

// ╔══════════════════════════════════════════════════════════╗
// ║  AI "TEACH ME THIS DASHBOARD" — context-aware quick start     ║
// ╚══════════════════════════════════════════════════════════╝
const DASHBOARD_AI_CONTEXT = `You are the built-in assistant inside "Emergens", a passive security-reconnaissance web console. Sections available to the user: Overview (quick scan + recent scans + network traffic), Security Testing (full scan with selectable tools, Basic/Expert mode), Scan History, System Console (server logs + CPU/RAM/disk), AI Assistant (this chat), Sekolah/School Search, Minecraft Server Status checker, Telegram Bot integration, Documentation, Preferences (storage + language), and for Owners: User Management, API Keys, and Theme Studio. There's also a draggable Quick Menu bubble (bottom-right) that pops open floating mini-windows for Basic/Expert Scan, History, Console, AI chat and Telegram without leaving the current page. When the user asks how to use the dashboard, answer ONLY using this feature list, in a friendly and concise way — do not invent features that aren't listed here.`;

function buildTeachMePrompt(){
    return `${DASHBOARD_AI_CONTEXT}\n\nGive the user a short, friendly walkthrough of what this dashboard can do and how to get started, as if you were a helpful onboarding guide.`;
}

document.getElementById('chatWindow').insertAdjacentHTML('beforebegin', '<button class="ai-quickstart-btn" id="aiTeachMeBtn"><i class="fas fa-graduation-cap"></i> Teach me how to use this dashboard</button>');
document.getElementById('aiTeachMeBtn').addEventListener('click', ()=>{
    sendChatMessage(buildTeachMePrompt(), document.getElementById('chatWindow'), null, document.getElementById('chatSendBtn'));
});

// ╔══════════════════════════════════════════════════════════╗
// ║  AUTO-OPEN CONSOLE AFTER SCAN (toggle-gated)                 ║
// ╚══════════════════════════════════════════════════════════╝
function maybeAutoOpenConsole(){
    if(!getAutoConsolePref())return;
    openFloatingWindow('console',{title:'System Console',icon:'fas fa-terminal',width:380,height:320,buildBody:buildConsolePopup});
}


// ╔══════════════════════════════════════════════════════════╗
// ║  MOBILE BOTTOM NAV — Home / Sec / Setting / Profile        ║
// ╚══════════════════════════════════════════════════════════╝
(function(){
    const items=document.querySelectorAll('.bottom-nav-item[data-bn-section]');
    items.forEach(btn=>{
        btn.addEventListener('click',()=>{
            const sec=btn.dataset.bnSection;
            const navBtn=document.querySelector(`.nav-item[data-section="${sec}"]`);
            if(navBtn){ navBtn.click(); }
            items.forEach(i=>i.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('bottomNavProfileBtn')?.classList.remove('active');
        });
    });
    document.getElementById('bottomNavProfileBtn')?.addEventListener('click',()=>{
        document.getElementById('sidebarProfileTrigger')?.click();
    });
    // Keep bottom nav in sync when a section changes via the sidebar directly
    window.addEventListener('section-change',(e)=>{
        const sec=e.detail;
        items.forEach(i=>i.classList.toggle('active', i.dataset.bnSection===sec));
    });
})();

// ╔══════════════════════════════════════════════════════════╗
// ║  TOOLS HUB — burger menu "Tools" button, 8-box grid         ║
// ╚══════════════════════════════════════════════════════════╝
const toolsHubModal=document.getElementById('toolsHubModal');
const toolsHubCard=toolsHubModal.querySelector('.tools-hub-card');
const toolsGridView=document.getElementById('toolsGridView');
const toolsHubBackBtn=document.getElementById('toolsHubBackBtn');
const toolsHubHeaderTitle=document.getElementById('toolsHubHeaderTitle');
const TOOL_TITLES={
    brat:'Brat Generator', reels:'Reels', osint:'OSINT', anime:'Anime',
    wifi:'Wifi Scanner', ipcheck:'IP Check', music:'Music Downloader',
    downloader:'Downloader', mctools:'MCTOOLS'
};
function openToolsHub(){
    toolsHubModal.hidden=false;
    showToolsGrid();
}
function closeToolsHub(){ toolsHubModal.hidden=true; toolsHubCard.classList.remove('is-fullscreen'); }
function showToolsGrid(){
    toolsGridView.hidden=false;
    document.querySelectorAll('.tool-detail').forEach(d=>d.hidden=true);
    toolsHubBackBtn.hidden=true;
    toolsHubHeaderTitle.innerHTML='<i class="fas fa-grip" style="color:var(--red-400);margin-right:6px;"></i><span data-i18n="th_hub_title">Tools</span>';
    toolsHubCard.classList.remove('is-fullscreen');
}
function showToolDetail(tool){
    toolsGridView.hidden=true;
    document.querySelectorAll('.tool-detail').forEach(d=>d.hidden=(d.id!==`toolDetail-${tool}`));
    toolsHubBackBtn.hidden=false;
    toolsHubHeaderTitle.textContent=TOOL_TITLES[tool]||'Tools';
    // Open every tool detail in a focused fullscreen workspace for a cleaner, professional feel.
    toolsHubCard.classList.add('is-fullscreen');
    if(tool==='wifi')initWifiPanelState();
}
document.getElementById('navToolsHub').addEventListener('click',openToolsHub);
document.getElementById('closeToolsHubModal').addEventListener('click',closeToolsHub);
toolsHubBackBtn.addEventListener('click',showToolsGrid);
toolsHubModal.addEventListener('click',(e)=>{ if(e.target===toolsHubModal)closeToolsHub(); });
document.querySelectorAll('.tool-box').forEach(box=>{
    box.addEventListener('click',()=>{
        const tool=box.dataset.tool;
        if(tool==='quickaccess'){ showComingSoonToast(); return; }
        showToolDetail(tool);
    });
});
function showComingSoonToast(){
    showToast('Quick Access — coming soon.', 'warning');
}

// Let each inline search field submit on Enter by clicking its paired action button.
[['reelsSearchInput','reelsSearchBtn'],['osintQueryInput','osintSearchBtn'],['animeSearchInput','animeSearchBtn'],['ipCheckInput','ipCheckBtn'],['musicQueryInput','musicFetchBtn'],['dlUrlInput','dlFetchBtn'],['mcSearchInput','mcSearchBtn']].forEach(([inputId,btnId])=>{
    const input=document.getElementById(inputId), btn=document.getElementById(btnId);
    if(!input||!btn)return;
    input.addEventListener('keydown',(e)=>{ if(e.key==='Enter'){ e.preventDefault(); if(!btn.disabled)btn.click(); } });
});

// Segmented-control helper: wires a group of .seg-btn buttons under a container,
// toggling .active and returning the selected value via a callback.
function wireSegmentedControl(containerEl, attr, onChange){
    if(!containerEl)return;
    containerEl.querySelectorAll('.seg-btn').forEach(btn=>{
        btn.addEventListener('click',()=>{
            containerEl.querySelectorAll('.seg-btn').forEach(b=>b.classList.remove('active'));
            btn.classList.add('active');
            onChange(btn.dataset[attr]);
        });
    });
}

// ╔══════════════════════════════════════════════════════════╗
// ║  TOOL API BASE URLS — fill these in once your backend       ║
// ║  endpoints exist. Left blank, each tool below falls back     ║
// ║  to the closest thing it can do without one (or shows an     ║
// ║  honest "not configured yet" state instead of fake data).    ║
// ╚══════════════════════════════════════════════════════════╝
const TOOL_API_BASE = {
    brat: 'https://api.siputzx.my.id/api/m/brat',  // Brat cover generator — GET ?q=<caption>
    anime: 'https://api.siputzx.my.id/api/s/otakotaku',  // GET ?q=<term> — OtakOtaku search via the siputzx API
    music: '',        // e.g. 'https://your-api.example.com/music'      — POST {query} -> {title,artist,audio_url,thumbnail}
    musicSearch: 'https://api.siputzx.my.id/api/s/applemusic',      // GET ?q=<term> -> {status,data:[{title,artist,link,image}],timestamp}
    osintTiktokUser: 'https://api.socialfetch.dev/v1/tiktok/users/search',  // GET ?query=<username>
    reels: 'https://api.socialfetch.dev/v1/tiktok/search',                 // GET ?query=<term>
    downloader: 'https://api.siputzx.my.id/api/d/tiktok/v2',  // TikTok downloader — GET ?url=<link>
    pinterest:  'https://api.siputzx.my.id/api/s/pinterest',  // Pinterest search  — GET ?q=<term>
    mcpedl:     'https://api.siputzx.my.id/api/s/mcpedl'      // Minecraft skin/mod/shader search — GET ?q=<term> -> {status,data:[{title,link,image,rating}],timestamp}
};
// NOTE (fixed): every api.siputzx.my.id endpoint above returned
// {"status":false,"error":"Query parameter 'q' is required","code":400}
// when called with ?query=/?text= — their router expects the single-letter
// ?q= parameter across the board. Each call below now sends ?q= as the real
// parameter, with the old name appended alongside it (harmless if unused) in
// case any one of these five endpoints turns out to read a different name.
// api.socialfetch.dev (OSINT / Reels) is a separate provider and is
// unaffected — it already uses ?query=, confirmed directly against the
// example URLs you provided for those two.
// NOTE on brat / osintTiktokUser / reels: only the endpoint paths above were specified
// when these were wired up — the exact query-parameter names and response shapes
// weren't verifiable against the live APIs from this environment (same situation as
// the AI Assistant integration further up this file). Brat generation tries both a
// raw-image response and a JSON-wrapped one, then falls back to the offline canvas
// renderer on any failure. OSINT and Reels parse their responses defensively via
// extractListFromResponse() below, trying several common field names per item and
// simply omitting a field it can't find rather than showing "undefined". If the live
// field names differ once you test against the real API, only the small render
// functions (renderOsintTiktokUsers / renderReelsResults) need adjusting.

// ╔══════════════════════════════════════════════════════════╗
// ║  BOX 1 — BRAT GENERATOR                                     ║
// ╚══════════════════════════════════════════════════════════╝
function renderBratCanvas(text, bg){
    const canvas=document.createElement('canvas');
    const SIZE=640;
    canvas.width=SIZE; canvas.height=SIZE;
    const ctx=canvas.getContext('2d');
    ctx.fillStyle=bg;
    ctx.fillRect(0,0,SIZE,SIZE);
    // luminance-based text color so it stays legible on any background
    const hex=bg.replace('#','');
    const rr=parseInt(hex.substring(0,2),16), gg=parseInt(hex.substring(2,4),16), bb=parseInt(hex.substring(4,6),16);
    const luminance=(0.299*rr+0.587*gg+0.114*bb)/255;
    ctx.fillStyle = luminance>0.6 ? '#111111' : '#f5f5f5';
    ctx.textAlign='center';
    ctx.textBaseline='middle';
    ctx.filter='blur(1.1px)';
    const words=(text||'brat').toLowerCase().split(/\s+/).filter(Boolean);
    let fontSize=Math.max(34, 92-words.join(' ').length*1.4);
    ctx.font=`700 ${fontSize}px Helvetica Neue, Arial, sans-serif`;
    // wrap into lines that fit within 86% of canvas width
    const maxWidth=SIZE*0.86;
    const lines=[]; let cur='';
    words.forEach(w=>{
        const test=cur?cur+' '+w:w;
        if(ctx.measureText(test).width>maxWidth && cur){ lines.push(cur); cur=w; } else { cur=test; }
    });
    if(cur)lines.push(cur);
    const lineHeight=fontSize*0.98;
    const totalHeight=lineHeight*lines.length;
    let y=SIZE/2 - totalHeight/2 + lineHeight/2;
    lines.forEach(line=>{ ctx.fillText(line, SIZE/2, y); y+=lineHeight; });
    ctx.filter='none';
    return canvas;
}
// Fetches the Brat cover from the external API. Handles two possible response
// shapes since it wasn't verifiable ahead of time which one the live endpoint
// uses: raw image bytes (read as a Blob and turned into an object URL), or a
// JSON body carrying a URL / base64 payload (read defensively, several likely
// field names tried in turn — same approach as the AI Assistant integration
// above and the Pinterest/TikTok-shape handling further down this file).
async function fetchBratImageSrc(text){
    const url=`${TOOL_API_BASE.brat}?q=${encodeURIComponent(text)}&text=${encodeURIComponent(text)}`;
    const r=await fetch(url);
    if(!r.ok)throw new Error('API error '+r.status);
    const contentType=r.headers.get('content-type')||'';
    if(contentType.startsWith('image/')){
        const blob=await r.blob();
        return URL.createObjectURL(blob);
    }
    const d=await r.json();
    const src=d.image_url || d.url || (d.data && (d.data.image_url||d.data.url)) || (d.image_base64?`data:image/png;base64,${d.image_base64}`:null);
    if(!src)throw new Error('Unexpected response shape from the Brat API');
    return src;
}
document.getElementById('bratGenerateBtn').addEventListener('click', async()=>{
    const text=document.getElementById('bratTextInput').value.trim()||'brat';
    const bg=document.getElementById('bratBgColor').value;
    const area=document.getElementById('bratResultArea');
    const btn=document.getElementById('bratGenerateBtn');
    btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner spin"></i> Generating...';
    try{
        if(TOOL_API_BASE.brat){
            const src=await fetchBratImageSrc(text);
            area.innerHTML=`<img src="${escapeHtml(src)}" class="tr-media-preview" alt="Brat cover"><a class="btn-secondary tr-download-btn" href="${escapeHtml(src)}" download="brat.png"><i class="fas fa-download"></i> Download</a>`;
        }else{
            const canvas=renderBratCanvas(text,bg);
            const dataUrl=canvas.toDataURL('image/png');
            area.innerHTML=`<img src="${dataUrl}" class="tr-media-preview" alt="Brat cover"><a class="btn-secondary tr-download-btn" href="${dataUrl}" download="brat.png"><i class="fas fa-download"></i> Download</a>`;
        }
    }catch(e){
        // The remote API failed, or returned something unexpected — fall back to
        // the offline renderer so the tool still produces a usable cover.
        const canvas=renderBratCanvas(text,bg);
        const dataUrl=canvas.toDataURL('image/png');
        area.innerHTML=`<div class="tr-config-note" style="margin-bottom:10px;"><i class="fas fa-triangle-exclamation"></i><span>Brat API request failed (${escapeHtml(e.message)}) — showing the offline-generated version instead.</span></div><img src="${dataUrl}" class="tr-media-preview" alt="Brat cover"><a class="btn-secondary tr-download-btn" href="${dataUrl}" download="brat.png"><i class="fas fa-download"></i> Download</a>`;
    }finally{
        btn.disabled=false; btn.innerHTML='<i class="fas fa-wand-magic-sparkles"></i> <span data-i18n="btn_generate">Generate</span>';
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  SHARED HELPERS — used by OSINT, Reels (and Music search)   ║
// ╚══════════════════════════════════════════════════════════╝
// Formats a raw count into a compact "1.2K" / "3.4M" style string.
function fmtCount(n){
    if(n===undefined||n===null||n==='')return '--';
    const num=Number(String(n).replace(/[^0-9.]/g,''));
    if(!isFinite(num)||/[KMB]/i.test(String(n)))return String(n);
    if(num>=1e6)return (num/1e6).toFixed(num>=1e7?0:1)+'M';
    if(num>=1e3)return (num/1e3).toFixed(num>=1e4?0:1)+'K';
    return String(num);
}
// Pulls a results array out of a JSON body without assuming one exact wrapper
// shape. Tries the raw value itself, then each dotted path in `candidates` in
// order (e.g. 'data', 'data.users'), and returns [] if nothing matches.
function extractListFromResponse(d, candidates){
    if(Array.isArray(d))return d;
    if(!d || typeof d!=='object')return [];
    for(const path of candidates){
        const v=path.split('.').reduce((o,key)=>(o&&typeof o==='object')?o[key]:undefined, d);
        if(Array.isArray(v))return v;
    }
    return [];
}

// ╔══════════════════════════════════════════════════════════╗
// ║  BOX 2 — REELS (TikTok video search)                         ║
// ║  GET {reels}?query=<term>   (socialfetch.dev)                 ║
// ╚══════════════════════════════════════════════════════════╝
function renderReelsResults(d, area, query){
    const videos=extractListFromResponse(d, ['data','result','results','videos','data.videos','data.data']);
    if(!videos.length){
        area.innerHTML=`<div class="empty-state"><strong>No videos found</strong><span class="hint">Nothing matched "${escapeHtml(query)}".</span></div>`;
        return;
    }
    area.innerHTML=`<div class="anime-search-heading">Results for "${escapeHtml(query)}"</div>
        <div class="reels-grid">${videos.slice(0,24).map(v=>{
            const desc = v.desc || v.description || v.title || v.caption || '';
            const cover = v.cover || v.origin_cover || v.thumbnail || (v.video && (v.video.cover||v.video.originCover)) || '';
            const playUrl = v.play || v.video_url || v.download_url || v.playAddr || (v.video && (v.video.playAddr||v.video.play)) || '';
            const author = (v.author && (v.author.nickname||v.author.uniqueId||v.author.username)) || v.author_name || v.username || '';
            const link = v.share_url || v.link || v.url || '';
            const stats = v.stats || {};
            const plays = stats.playCount ?? v.play_count ?? v.views;
            const likes = stats.diggCount ?? v.like_count ?? v.likes;
            return `<div class="reel-card">
                <div class="reel-card-media">${
                    playUrl ? `<video src="${escapeHtml(playUrl)}" ${cover?`poster="${escapeHtml(cover)}"`:''} controls playsinline preload="none"></video>`
                    : (cover ? `<img src="${escapeHtml(cover)}" alt="" loading="lazy" onerror="this.style.display='none'">` : '<i class="fas fa-clapperboard"></i>')
                }</div>
                <div class="reel-card-body">
                    ${desc?`<div class="reel-card-desc">${escapeHtml(desc)}</div>`:''}
                    <div class="reel-card-meta">
                        ${author?`<span><i class="fas fa-user"></i> ${escapeHtml(author)}</span>`:''}
                        ${plays!==undefined&&plays!==null?`<span><i class="fas fa-play"></i> ${escapeHtml(fmtCount(plays))}</span>`:''}
                        ${likes!==undefined&&likes!==null?`<span><i class="fas fa-heart"></i> ${escapeHtml(fmtCount(likes))}</span>`:''}
                    </div>
                    ${link?`<a class="reel-card-open" href="${escapeHtml(link)}" target="_blank" rel="noopener"><i class="fas fa-up-right-from-square"></i> Open on TikTok</a>`:''}
                </div>
            </div>`;
        }).join('')}</div>`;
}
document.getElementById('reelsSearchBtn').addEventListener('click', async()=>{
    const q=document.getElementById('reelsSearchInput').value.trim();
    const area=document.getElementById('reelsResultArea');
    if(!q){ showToast('Type something to search.','error'); return; }
    const btn=document.getElementById('reelsSearchBtn');
    btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner spin"></i> Searching...';
    area.innerHTML=`<div class="tr-loading"><i class="fas fa-spinner spin"></i> Searching TikTok…</div>`;
    try{
        const r=await fetch(`${TOOL_API_BASE.reels}?query=${encodeURIComponent(q)}`);
        if(!r.ok)throw new Error('API error '+r.status);
        const d=await r.json();
        if(d && d.status===false)throw new Error(d.message||'Search failed');
        renderReelsResults(d, area, q);
    }catch(e){
        area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Search failed: ${escapeHtml(e.message)}</div>`;
    }finally{
        btn.disabled=false; btn.innerHTML='<i class="fas fa-search"></i> <span data-i18n="btn_search">Search</span>';
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  BOX — MUSIC DOWNLOADER (Apple Music search + direct fetch) ║
// ║  Search : GET  {musicSearch}?query=<term>   (Apple Music)    ║
// ║  Direct : POST {music} {query} -> {title,artist,audio_url}   ║
// ╚══════════════════════════════════════════════════════════╝
function renderMusicSearchResults(d, area, query){
    const items=extractListFromResponse(d, ['data','result','results']);
    if(!items.length){
        area.innerHTML=`<div class="empty-state"><strong>No results</strong><span class="hint">Nothing matched "${escapeHtml(query)}".</span></div>`;
        return;
    }
    area.innerHTML=`<div class="anime-search-heading">Results for "${escapeHtml(query)}"</div>
        <div class="music-search-grid">${items.slice(0,30).map(it=>{
            const title=it.title||'Untitled';
            // The sample payload sometimes runs a trailing "Lyrics: ..." excerpt
            // straight into the artist field with no separator — trimmed here
            // so the card shows a clean artist/type line.
            const artist=String(it.artist||'').replace(/Lyrics:.*/is,'').trim();
            const image=it.image||'';
            const link=it.link||'';
            return `<a class="music-card" href="${escapeHtml(link)}" target="_blank" rel="noopener">
                <div class="music-card-art">${image?`<img src="${escapeHtml(image)}" alt="" loading="lazy" onerror="this.remove()">`:'<i class="fas fa-music"></i>'}</div>
                <div class="music-card-body">
                    <div class="music-card-title">${escapeHtml(title)}</div>
                    ${artist?`<div class="music-card-artist">${escapeHtml(artist)}</div>`:''}
                </div>
                <i class="fas fa-arrow-up-right-from-square music-card-open"></i>
            </a>`;
        }).join('')}</div>`;
}
document.getElementById('musicFetchBtn').addEventListener('click', async()=>{
    const q=document.getElementById('musicQueryInput').value.trim();
    const area=document.getElementById('musicResultArea');
    const btn=document.getElementById('musicFetchBtn');
    if(!q){ showToast('Enter a song name or link first.','error'); return; }
    const isLink=/^https?:\/\//i.test(q);
    if(isLink){
        if(!TOOL_API_BASE.music){
            area.innerHTML=`<div class="tr-config-note"><i class="fas fa-plug-circle-xmark"></i><span>Direct-link fetching isn't configured yet. Set <code>TOOL_API_BASE.music</code> in script.js to enable it, or search by song name instead.</span></div>`;
            return;
        }
        btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner spin"></i> Fetching...';
        try{
            const r=await fetch(TOOL_API_BASE.music,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:q})});
            if(!r.ok)throw new Error('API error '+r.status);
            const d=await r.json();
            if(!d.audio_url)throw new Error('No audio returned');
            area.innerHTML=`<div class="tr-card"><div class="tr-row"><span class="tr-k">Title</span><span class="tr-v">${escapeHtml(d.title||'--')}</span></div><div class="tr-row"><span class="tr-k">Artist</span><span class="tr-v">${escapeHtml(d.artist||'--')}</span></div></div><audio src="${escapeHtml(d.audio_url)}" controls style="width:100%;margin-top:10px;"></audio><a class="btn-secondary tr-download-btn" href="${escapeHtml(d.audio_url)}" download target="_blank" rel="noopener"><i class="fas fa-download"></i> Download</a>`;
        }catch(e){
            area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Couldn't fetch: ${escapeHtml(e.message)}</div>`;
        }finally{
            btn.disabled=false; btn.innerHTML='<i class="fas fa-search"></i> <span data-i18n="btn_search">Search</span>';
        }
    }else{
        btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner spin"></i> Searching...';
        area.innerHTML=`<div class="tr-loading"><i class="fas fa-spinner spin"></i> Searching Apple Music…</div>`;
        try{
            const r=await fetch(`${TOOL_API_BASE.musicSearch}?q=${encodeURIComponent(q)}&query=${encodeURIComponent(q)}`);
            if(!r.ok)throw new Error('API error '+r.status);
            const d=await r.json();
            if(d && d.status===false)throw new Error(d.message||'Search failed');
            renderMusicSearchResults(d, area, q);
        }catch(e){
            area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Search failed: ${escapeHtml(e.message)}</div>`;
        }finally{
            btn.disabled=false; btn.innerHTML='<i class="fas fa-search"></i> <span data-i18n="btn_search">Search</span>';
        }
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  BOX 9 — DOWNLOADER (TikTok download / Pinterest search)    ║
// ║  TikTok   : GET  {downloader}?url=<link>   (siputzx v2)      ║
// ║  Pinterest: GET  {pinterest}?query=<term>  (image search)    ║
// ╚══════════════════════════════════════════════════════════╝
let dlPlatform='tiktok';
const dlInput=document.getElementById('dlUrlInput');
const dlBtn=document.getElementById('dlFetchBtn');
const dlBtnLabel={
    tiktok:'<i class="fas fa-download"></i> <span>Fetch</span>',
    pinterest:'<i class="fas fa-search"></i> <span>Search</span>'
};
function dlApplyPlatform(v){
    dlPlatform=v;
    dlInput.value='';
    dlInput.placeholder = v==='pinterest' ? 'Search Pinterest images…' : 'https://www.tiktok.com/@user/video/…';
    dlBtn.innerHTML = dlBtnLabel[v];
    const area=document.getElementById('dlResultArea'); if(area)area.innerHTML='';
}
wireSegmentedControl(document.getElementById('dlPlatformToggle'),'platform',dlApplyPlatform);
function renderTiktokResult(d, area){
    if(!d || d.status===false || !d.data) throw new Error(d && d.message ? d.message : 'No media returned');
    const v=d.data;
    const src = v.no_watermark_link_hd || v.no_watermark_link || v.watermark_link || '';
    const cover = v.cover_link || v.origin_cover || '';
    if(!src && !v.music_link) throw new Error('No downloadable media in the response');
    const stats=[['fa-play','Views',v.play_count],['fa-heart','Likes',v.like_count],['fa-comment','Comments',v.comment_count],['fa-share','Shares',v.share_count]];
    area.innerHTML=`<div class="dl-result">
        ${src?`<video class="dl-video" src="${escapeHtml(src)}" ${cover?`poster="${escapeHtml(cover)}"`:''} controls playsinline preload="metadata"></video>`:''}
        <div class="dl-meta">
            <div class="dl-author">${v.author_cover_link?`<img class="dl-avatar" src="${escapeHtml(v.author_cover_link)}" alt="" onerror="this.remove()">`:'<i class="fas fa-user-circle"></i>'}<span>${escapeHtml(v.author_nickname||'Unknown creator')}</span></div>
            <div class="dl-stats">${stats.map(([ic,label,val])=>`<div class="dl-stat"><i class="fas ${ic}"></i><span class="dl-stat-v">${escapeHtml(fmtCount(val))}</span><span class="dl-stat-l">${label}</span></div>`).join('')}</div>
            ${v.music_link?`<div class="dl-audio-wrap"><span class="dl-audio-label"><i class="fas fa-music"></i> Original sound</span><audio class="dl-audio" src="${escapeHtml(v.music_link)}" controls preload="none"></audio></div>`:''}
        </div>
    </div>`;
}
function renderPinterestResults(d, area, query){
    const raw = Array.isArray(d) ? d : (d && (d.data || d.result || d.results)) || [];
    const items = (Array.isArray(raw)?raw:[]).map(it=>{
        if(typeof it==='string') return {image:it, link:it};
        return {
            image: it.image_url || it.images_url || it.image || it.thumbnail || it.media || it.url || '',
            link:  it.pin || it.link || it.source || it.url || ''
        };
    }).filter(x=>x.image);
    if(!items.length){
        area.innerHTML=`<div class="empty-state"><strong>No results</strong><span class="hint">Nothing matched "${escapeHtml(query)}".</span></div>`;
        return;
    }
    area.innerHTML=`<div class="anime-search-heading">Results for "${escapeHtml(query)}"</div>
        <div class="pin-grid">${items.slice(0,48).map(x=>`<a class="pin-card" href="${escapeHtml(x.link||x.image)}" target="_blank" rel="noopener"><img src="${escapeHtml(x.image)}" loading="lazy" alt="" onerror="this.closest('.pin-card').remove()"><span class="pin-open"><i class="fas fa-up-right-from-square"></i></span></a>`).join('')}</div>`;
}
dlBtn.addEventListener('click', async()=>{
    const val=dlInput.value.trim();
    const area=document.getElementById('dlResultArea');
    if(!val){ showToast(dlPlatform==='pinterest'?'Type something to search.':'Paste a TikTok link first.','error'); return; }
    const base = dlPlatform==='pinterest' ? TOOL_API_BASE.pinterest : TOOL_API_BASE.downloader;
    if(!base){
        area.innerHTML=`<div class="tr-config-note"><i class="fas fa-plug-circle-xmark"></i><span>This endpoint isn't configured yet in <code>TOOL_API_BASE</code>.</span></div>`;
        return;
    }
    dlBtn.disabled=true; dlBtn.innerHTML=`<i class="fas fa-spinner spin"></i> ${dlPlatform==='pinterest'?'Searching…':'Fetching…'}`;
    area.innerHTML=`<div class="tr-loading"><i class="fas fa-spinner spin"></i> ${dlPlatform==='pinterest'?'Searching Pinterest…':'Grabbing the video…'}</div>`;
    try{
        const q = dlPlatform==='pinterest' ? `?q=${encodeURIComponent(val)}&query=${encodeURIComponent(val)}` : `?url=${encodeURIComponent(val)}`;
        const r=await fetch(base+q);
        if(!r.ok)throw new Error('API error '+r.status);
        const d=await r.json();
        if(dlPlatform==='pinterest') renderPinterestResults(d, area, val);
        else renderTiktokResult(d, area);
    }catch(e){
        area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ${dlPlatform==='pinterest'?'Search failed':"Couldn't fetch"}: ${escapeHtml(e.message)}</div>`;
    }finally{
        dlBtn.disabled=false; dlBtn.innerHTML=dlBtnLabel[dlPlatform];
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  BOX 10 — MCTOOLS (Minecraft skin / mod / shader search)     ║
// ║  GET {mcpedl}?query=<term>   (siputzx, sourced from MCPEDL)   ║
// ╚══════════════════════════════════════════════════════════╝
// 8x8 pixel-grid Creeper face — plain SVG rects on a grid (the classic
// resolution for a Minecraft mob head), no image asset required, so it
// stays crisp at any size and costs nothing to load. Animated in CSS
// with a "charge and flash" pulse (see .mc-creeper) while a search runs.
const MC_CREEPER_SVG = `<svg class="mc-creeper" viewBox="0 0 8 8" shape-rendering="crispEdges" aria-hidden="true">
    <rect width="8" height="8" class="mc-face-bg"/>
    <rect x="1" y="1" width="1" height="1" class="mc-face-pixel"/><rect x="2" y="1" width="1" height="1" class="mc-face-pixel"/>
    <rect x="5" y="1" width="1" height="1" class="mc-face-pixel"/><rect x="6" y="1" width="1" height="1" class="mc-face-pixel"/>
    <rect x="1" y="2" width="1" height="1" class="mc-face-pixel"/><rect x="2" y="2" width="1" height="1" class="mc-face-pixel"/>
    <rect x="5" y="2" width="1" height="1" class="mc-face-pixel"/><rect x="6" y="2" width="1" height="1" class="mc-face-pixel"/>
    <rect x="3" y="3" width="1" height="1" class="mc-face-pixel"/><rect x="4" y="3" width="1" height="1" class="mc-face-pixel"/>
    <rect x="2" y="4" width="1" height="1" class="mc-face-pixel"/><rect x="3" y="4" width="1" height="1" class="mc-face-pixel"/><rect x="4" y="4" width="1" height="1" class="mc-face-pixel"/><rect x="5" y="4" width="1" height="1" class="mc-face-pixel"/>
    <rect x="2" y="5" width="1" height="1" class="mc-face-pixel"/><rect x="3" y="5" width="1" height="1" class="mc-face-pixel"/><rect x="4" y="5" width="1" height="1" class="mc-face-pixel"/><rect x="5" y="5" width="1" height="1" class="mc-face-pixel"/>
    <rect x="2" y="6" width="1" height="1" class="mc-face-pixel"/><rect x="5" y="6" width="1" height="1" class="mc-face-pixel"/>
</svg>`;
function mcLoadingMarkup(label){
    return `<div class="mc-loading">${MC_CREEPER_SVG}<span class="mc-loading-text">${escapeHtml(label||'Loading Minecraft content…')}</span></div>`;
}
function renderMcpedlResults(d, area, query){
    const items=extractListFromResponse(d, ['data','result','results']);
    if(!items.length){
        area.innerHTML=`<div class="empty-state"><strong>No results</strong><span class="hint">Nothing matched "${escapeHtml(query)}".</span></div>`;
        return;
    }
    area.innerHTML=`<div class="anime-search-heading">Results for "${escapeHtml(query)}"</div>
        <div class="mc-search-grid">${items.slice(0,30).map(it=>{
            const title=it.title||'Untitled';
            const image=it.image||'';
            const link=it.link||'';
            const rating=parseFloat(it.rating);
            const hasRating=!isNaN(rating);
            return `<a class="mc-card" href="${escapeHtml(link)}" target="_blank" rel="noopener">
                <div class="mc-card-thumb">${image?`<img src="${escapeHtml(image)}" alt="" loading="lazy" onerror="this.remove()">`:'<i class="fas fa-cube"></i>'}</div>
                <div class="mc-card-body">
                    <div class="mc-card-title">${escapeHtml(title)}</div>
                    ${hasRating?`<div class="mc-card-rating"><i class="fas fa-star"></i> ${rating.toFixed(1)}</div>`:''}
                </div>
            </a>`;
        }).join('')}</div>`;
}
document.getElementById('mcSearchBtn').addEventListener('click', async()=>{
    const q=document.getElementById('mcSearchInput').value.trim();
    const area=document.getElementById('mcResultArea');
    if(!q){ showToast('Type something to search.','error'); return; }
    const btn=document.getElementById('mcSearchBtn');
    btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner spin"></i> Searching...';
    area.innerHTML=mcLoadingMarkup(`Searching for "${q}"…`);
    try{
        const r=await fetch(`${TOOL_API_BASE.mcpedl}?q=${encodeURIComponent(q)}&query=${encodeURIComponent(q)}`);
        if(!r.ok)throw new Error('API error '+r.status);
        const d=await r.json();
        if(d && d.status===false)throw new Error(d.message||'Search failed');
        renderMcpedlResults(d, area, q);
    }catch(e){
        area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Search failed: ${escapeHtml(e.message)}</div>`;
    }finally{
        btn.disabled=false; btn.innerHTML='<i class="fas fa-search"></i> <span data-i18n="btn_search">Search</span>';
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  BOX 4 — ANIME SEARCH                                        ║
// ╚══════════════════════════════════════════════════════════╝
function renderAnimeCategory(label, iconClass, items){
    if(!items || !items.length) return '';
    return `<div class="anime-category">
        <div class="anime-category-title"><i class="fas ${iconClass}"></i> ${escapeHtml(label)} <span class="anime-category-count">${items.length}</span></div>
        <div class="anime-result-grid">${items.slice(0,24).map(item=>{
            const title = item.title || 'Untitled';
            const thumb = item.imageUrl || item.thumbnail || item.image || '';
            const link = item.url || '';
            const card = `<div class="anime-card">
                <div class="anime-card-thumb">${thumb?`<img src="${escapeHtml(thumb)}" alt="${escapeHtml(title)}" loading="lazy" onerror="this.style.display='none';this.nextElementSibling.style.display='block';"><i class="fas ${iconClass}" style="display:none;"></i>`:`<i class="fas ${iconClass}"></i>`}</div>
                <div class="anime-card-title">${escapeHtml(title)}</div>
            </div>`;
            return link ? `<a href="${escapeHtml(link)}" target="_blank" rel="noopener" style="text-decoration:none;color:inherit;">${card}</a>` : card;
        }).join('')}</div>
    </div>`;
}
document.getElementById('animeSearchBtn').addEventListener('click', async()=>{
    const q=document.getElementById('animeSearchInput').value.trim();
    const area=document.getElementById('animeResultArea');
    if(!q){ showToast('Type something to search.','error'); return; }
    if(!TOOL_API_BASE.anime){
        area.innerHTML=`<div class="tr-config-note"><i class="fas fa-plug-circle-xmark"></i><span>Anime API base URL isn't configured yet. Set <code>TOOL_API_BASE.anime</code> in script.js to enable search.</span></div>`;
        return;
    }
    const btn=document.getElementById('animeSearchBtn');
    btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner spin"></i> Searching...';
    try{
        const r=await fetch(`${TOOL_API_BASE.anime}?q=${encodeURIComponent(q)}&query=${encodeURIComponent(q)}`);
        if(!r.ok)throw new Error('API error '+r.status);
        const d=await r.json();
        if(d.status===false)throw new Error(d.message||'Search failed');
        // Real shape: { status, data: { headline, anime:[], karakter:[], artikel:[] }, timestamp }
        const payload = d.data || d;
        const animeList = payload.anime || [];
        const charList = payload.karakter || payload.characters || [];
        const articleList = payload.artikel || payload.articles || [];
        if(!animeList.length && !charList.length && !articleList.length){
            area.innerHTML=`<div class="empty-state"><strong>No results</strong><span class="hint">Try a different title.</span></div>`;
            return;
        }
        area.innerHTML = `<div class="anime-search-heading">Results for "${escapeHtml(q)}"</div>`
            + renderAnimeCategory('Anime', 'fa-clapperboard', animeList)
            + renderAnimeCategory('Characters', 'fa-user', charList)
            + renderAnimeCategory('Articles', 'fa-newspaper', articleList);
    }catch(e){
        area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Search failed: ${escapeHtml(e.message)}</div>`;
    }finally{
        btn.disabled=false; btn.innerHTML='<i class="fas fa-search"></i> <span data-i18n="btn_search">Search</span>';
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  BOX 3 — OSINT (username / email / number lookup)           ║
// ║  Username    : GET {osintTiktokUser}?query=<name> (socialfetch.dev) ║
// ║  Email/Number: still calls YOUR OWN backend: POST /api/osint/search ║
// ║    request  { method: "email"|"number", query }               ║
// ║    response { sources: [ { name, found, data, url } ] }       ║
// ║    or a 404 if modules/osint.py isn't present on the server.  ║
// ╚══════════════════════════════════════════════════════════╝
let osintMethod='username';
wireSegmentedControl(document.getElementById('osintMethodToggle'),'method',(v)=>{
    osintMethod=v;
    const ph={username:'Enter a username...',email:'Enter an email address...',number:'Enter a phone number...'};
    document.getElementById('osintQueryInput').placeholder=ph[v]||'';
});
function renderOsintTiktokUsers(d, area, query){
    const users=extractListFromResponse(d, ['data','result','results','users','data.users']);
    if(!users.length){
        area.innerHTML=`<div class="empty-state"><strong>No profiles found</strong><span class="hint">"${escapeHtml(query)}" didn't match any TikTok accounts.</span></div>`;
        return;
    }
    area.innerHTML=users.slice(0,24).map(u=>{
        const username = u.username || u.uniqueId || u.unique_id || u.handle || '';
        const nickname = u.nickname || u.display_name || u.full_name || username || 'Unknown';
        const avatar = u.avatar || u.avatarThumb || u.avatar_url || u.avatarLarger || u.profile_pic || '';
        const bio = u.bio || u.signature || u.description || '';
        const followers = u.followers ?? u.followerCount ?? u.follower_count ?? (u.stats && (u.stats.followerCount ?? u.stats.followers));
        const verified = !!(u.verified ?? u.is_verified ?? u.isVerified);
        const link = u.url || u.link || u.share_url || (username?`https://www.tiktok.com/@${username}`:'');
        return `<div class="osint-profile-card">
            <div class="osint-profile-avatar">${avatar?`<img src="${escapeHtml(avatar)}" alt="" loading="lazy" onerror="this.remove()">`:'<i class="fas fa-user"></i>'}</div>
            <div class="osint-profile-body">
                <div class="osint-profile-name">${escapeHtml(nickname)}${verified?' <i class="fas fa-circle-check osint-verified" title="Verified"></i>':''}</div>
                ${username?`<div class="osint-profile-handle">@${escapeHtml(username)}</div>`:''}
                ${bio?`<div class="osint-profile-bio">${escapeHtml(bio)}</div>`:''}
                ${followers!==undefined&&followers!==null?`<div class="osint-profile-followers"><i class="fas fa-users"></i> ${escapeHtml(fmtCount(followers))} followers</div>`:''}
            </div>
            ${link?`<a class="btn-secondary osint-profile-link" href="${escapeHtml(link)}" target="_blank" rel="noopener"><i class="fab fa-tiktok"></i> View</a>`:''}
        </div>`;
    }).join('');
}
document.getElementById('osintSearchBtn').addEventListener('click', async()=>{
    const query=document.getElementById('osintQueryInput').value.trim();
    const area=document.getElementById('osintResultArea');
    if(!query){ showToast('Enter a value to search first.','error'); return; }
    const btn=document.getElementById('osintSearchBtn');
    btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner spin"></i> Searching...';
    area.innerHTML='';

    if(osintMethod==='username'){
        area.innerHTML=`<div class="tr-loading"><i class="fas fa-spinner spin"></i> Searching TikTok…</div>`;
        try{
            const r=await fetch(`${TOOL_API_BASE.osintTiktokUser}?query=${encodeURIComponent(query)}`);
            if(!r.ok)throw new Error('API error '+r.status);
            const d=await r.json();
            if(d && d.status===false)throw new Error(d.message||'Search failed');
            renderOsintTiktokUsers(d, area, query);
        }catch(e){
            area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Search failed: ${escapeHtml(e.message)}</div>`;
        }finally{
            btn.disabled=false; btn.innerHTML='<i class="fas fa-search"></i> <span data-i18n="btn_search">Search</span>';
        }
        return;
    }

    try{
        const r=await fetch('/api/osint/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method:osintMethod,query})});
        if(r.status===404){
            area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> 404 — the OSINT module wasn't found on the server (modules/osint.py missing).</div>`;
            return;
        }
        if(!r.ok)throw new Error('Server error '+r.status);
        const d=await r.json();
        const sources = d.sources || d.results || (Array.isArray(d)?d:[]);
        if(!sources.length){
            area.innerHTML=`<div class="empty-state"><strong>No data found</strong><span class="hint">"${escapeHtml(query)}" didn't match anything in the connected sources.</span></div>`;
            return;
        }
        area.innerHTML=sources.map(s=>{
            const found = s.found!==undefined ? !!s.found : !!(s.data);
            return `<div class="tr-card">
                <div class="tr-row">
                    <span class="tr-k">${escapeHtml(s.name||s.source||'Source')}</span>
                    <span class="tr-v ${found?'tr-status-found':'tr-status-notfound'}"><i class="fas fa-${found?'circle-check':'circle-minus'}"></i> ${found?'Found':'Not found'}</span>
                </div>
                ${found && s.url ? `<div class="tr-row"><span class="tr-k">Link</span><span class="tr-v"><a href="${escapeHtml(s.url)}" target="_blank" rel="noopener">${escapeHtml(s.url)}</a></span></div>` : ''}
                ${found && s.data && typeof s.data==='object' ? Object.entries(s.data).map(([k,v])=>`<div class="tr-row"><span class="tr-k">${escapeHtml(k)}</span><span class="tr-v">${escapeHtml(String(v))}</span></div>`).join('') : ''}
            </div>`;
        }).join('');
    }catch(e){
        area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Search failed: ${escapeHtml(e.message)}</div>`;
    }finally{
        btn.disabled=false; btn.innerHTML='<i class="fas fa-search"></i> <span data-i18n="btn_search">Search</span>';
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  BOX 5 — WIFI SCANNER                                        ║
// ║  Honest implementation: no browser on any platform exposes    ║
// ║  a list of nearby Wi-Fi network names to a webpage — this is  ║
// ║  intentionally blocked for privacy at the OS/browser level.   ║
// ║  What we CAN show, with permission: connection type/speed      ║
// ║  (Network Information API, Chrome/Android mostly) and an       ║
// ║  approximate location (Geolocation API).                       ║
// ╚══════════════════════════════════════════════════════════╝
function initWifiPanelState(){ /* no-op placeholder for future state resets */ }
document.getElementById('wifiRequestBtn').addEventListener('click', async()=>{
    const area=document.getElementById('wifiResultArea');
    const btn=document.getElementById('wifiRequestBtn');
    btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner spin"></i> Checking...';
    let rows='';

    // Network Information API (connection type/speed) — Chrome/Android mainly
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if(conn){
        rows += `<div class="tr-card">
            <div class="tr-row"><span class="tr-k">Connection type</span><span class="tr-v">${escapeHtml(conn.type||conn.effectiveType||'unknown')}</span></div>
            ${conn.effectiveType?`<div class="tr-row"><span class="tr-k">Effective speed class</span><span class="tr-v">${escapeHtml(conn.effectiveType)}</span></div>`:''}
            ${conn.downlink!==undefined?`<div class="tr-row"><span class="tr-k">Downlink</span><span class="tr-v">${conn.downlink} Mb/s</span></div>`:''}
            ${conn.rtt!==undefined?`<div class="tr-row"><span class="tr-k">Round-trip time</span><span class="tr-v">${conn.rtt} ms</span></div>`:''}
            <div class="tr-row"><span class="tr-k">Online</span><span class="tr-v">${navigator.onLine?'Yes':'No'}</span></div>
        </div>`;
    }else{
        rows += `<div class="tr-card"><div class="tr-row"><span class="tr-k">Online</span><span class="tr-v">${navigator.onLine?'Yes':'No'}</span></div><div class="tr-row"><span class="tr-k">Connection details</span><span class="tr-v tr-status-notfound">Not exposed by this browser</span></div></div>`;
    }

    // Approximate location via Geolocation permission (closest real "permission" flow)
    if(navigator.geolocation){
        try{
            const pos = await new Promise((res,rej)=>navigator.geolocation.getCurrentPosition(res,rej,{timeout:8000}));
            rows += `<div class="tr-card">
                <div class="tr-row"><span class="tr-k">Approx. latitude</span><span class="tr-v">${pos.coords.latitude.toFixed(5)}</span></div>
                <div class="tr-row"><span class="tr-k">Approx. longitude</span><span class="tr-v">${pos.coords.longitude.toFixed(5)}</span></div>
                <div class="tr-row"><span class="tr-k">Accuracy</span><span class="tr-v">±${Math.round(pos.coords.accuracy)} m</span></div>
            </div>`;
        }catch(geoErr){
            rows += `<div class="tr-card"><div class="tr-row"><span class="tr-k">Location</span><span class="tr-v tr-status-notfound">${geoErr.code===1?'Permission denied':'Unavailable'}</span></div></div>`;
        }
    }

    area.innerHTML = rows;
    btn.disabled=false; btn.innerHTML='<i class="fas fa-wifi"></i> <span data-i18n="wifi_request_btn">Check Network Info</span>';
});

// ╔══════════════════════════════════════════════════════════╗
// ║  BOX 6 — IP CHECK (real, public, free geolocation APIs)     ║
// ╚══════════════════════════════════════════════════════════╝
async function runIpLookup(query){
    const area=document.getElementById('ipCheckResultArea');
    area.innerHTML='<div class="empty-state"><i class="fas fa-spinner spin"></i> Looking up...</div>';
    try{
        const r=await fetch(`https://ipwho.is/${encodeURIComponent(query)}`);
        const d=await r.json();
        if(d.success===false){
            area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> ${escapeHtml(d.message||'Lookup failed — check the value and try again.')}</div>`;
            return;
        }
        area.innerHTML=`<div class="tr-card">
            <div class="tr-row"><span class="tr-k">IP</span><span class="tr-v">${escapeHtml(d.ip||query)}</span></div>
            <div class="tr-row"><span class="tr-k">Country</span><span class="tr-v">${escapeHtml(d.country||'--')} ${d.country_code?`(${escapeHtml(d.country_code)})`:''}</span></div>
            <div class="tr-row"><span class="tr-k">Region</span><span class="tr-v">${escapeHtml(d.region||'--')}</span></div>
            <div class="tr-row"><span class="tr-k">City</span><span class="tr-v">${escapeHtml(d.city||'--')}</span></div>
            <div class="tr-row"><span class="tr-k">ISP / Org</span><span class="tr-v">${escapeHtml(d.connection?.isp || d.connection?.org || '--')}</span></div>
            <div class="tr-row"><span class="tr-k">ASN</span><span class="tr-v">${escapeHtml(String(d.connection?.asn ?? '--'))}</span></div>
            <div class="tr-row"><span class="tr-k">Timezone</span><span class="tr-v">${escapeHtml(d.timezone?.id||'--')}</span></div>
            <div class="tr-row"><span class="tr-k">Coordinates</span><span class="tr-v">${d.latitude!==undefined?`${d.latitude}, ${d.longitude}`:'--'}</span></div>
        </div>`;
    }catch(e){
        area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Lookup failed: ${escapeHtml(e.message)}</div>`;
    }
}
document.getElementById('ipCheckBtn').addEventListener('click', ()=>{
    const q=document.getElementById('ipCheckInput').value.trim();
    if(!q){ showToast('Enter an IP or domain first.','error'); return; }
    runIpLookup(q);
});
document.getElementById('ipCheckMineBtn').addEventListener('click', async()=>{
    const ok=confirm('This will look up your own public IP address and its approximate location. Continue?');
    if(!ok)return;
    const area=document.getElementById('ipCheckResultArea');
    area.innerHTML='<div class="empty-state"><i class="fas fa-spinner spin"></i> Detecting your IP...</div>';
    try{
        const r=await fetch('https://api.ipify.org?format=json');
        const d=await r.json();
        document.getElementById('ipCheckInput').value=d.ip;
        await runIpLookup(d.ip);
    }catch(e){
        area.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Couldn't detect your IP: ${escapeHtml(e.message)}</div>`;
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  PRAYER TIMES — Malaysia & Indonesia (Overview)              ║
// ║  Source: Aladhan API (free, no key). Method codes below are  ║
// ║  our best-known mapping (17=JAKIM/Malaysia, 20=Kemenag/       ║
// ║  Indonesia) — double check against api.aladhan.com/           ║
// ║  calculation-methods-for-prayer-times and adjust if needed.   ║
// ╚══════════════════════════════════════════════════════════╝
const PRAYER_CONFIG = {
    MY: { method: 17, countryName: 'Malaysia', cities: ['Kuala Lumpur','Johor Bahru','George Town','Ipoh','Kuching','Kota Kinabalu','Shah Alam','Malacca City'] },
    ID: { method: 20, countryName: 'Indonesia', cities: ['Jakarta','Surabaya','Bandung','Medan','Semarang','Makassar','Yogyakarta','Denpasar'] }
};
let prayerCountry='MY';
function populatePrayerCitySelect(){
    const sel=document.getElementById('prayerCitySelect');
    if(!sel)return;
    sel.innerHTML=PRAYER_CONFIG[prayerCountry].cities.map(c=>`<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
}
async function loadPrayerTimes(){
    const grid=document.getElementById('prayerTimesGrid');
    const banner=document.getElementById('prayerNextBanner');
    if(!grid)return;
    const citySel=document.getElementById('prayerCitySelect');
    const city=citySel.value||PRAYER_CONFIG[prayerCountry].cities[0];
    const {method,countryName}=PRAYER_CONFIG[prayerCountry];
    grid.innerHTML='<div class="empty-state"><i class="fas fa-spinner spin"></i> <span data-i18n="loading">Loading...</span></div>';
    try{
        const r=await fetch(`https://api.aladhan.com/v1/timingsByCity?city=${encodeURIComponent(city)}&country=${encodeURIComponent(countryName)}&method=${method}`);
        const d=await r.json();
        if(!d.data || !d.data.timings) throw new Error('No timing data in response');
        const t=d.data.timings;
        const order=[['Fajr','Fajr'],['Dhuhr','Dhuhr'],['Asr','Asr'],['Maghrib','Maghrib'],['Isha','Isha']];
        const now=new Date();
        const parsed=order.map(([key,label])=>{
            const raw=(t[key]||'--').split(' ')[0];
            const [h,m]=raw.split(':').map(Number);
            const dt=new Date(now); dt.setHours(h||0,m||0,0,0);
            return {label,time:raw,dt};
        });
        let next=parsed.find(p=>p.dt.getTime()>now.getTime());
        grid.innerHTML=parsed.map(p=>`<div class="prayer-time-item ${next&&p.label===next.label?'is-next':''}"><div class="pt-name">${p.label}</div><div class="pt-time">${escapeHtml(p.time)}</div></div>`).join('');
        if(next){
            const mins=Math.max(0,Math.round((next.dt.getTime()-now.getTime())/60000));
            const hh=Math.floor(mins/60), mm=mins%60;
            banner.hidden=false;
            banner.innerHTML=`<i class="fas fa-mosque"></i> <span><strong>${escapeHtml(next.label)}</strong> in ${hh>0?hh+'h ':''}${mm}m</span>`;
        }else{
            banner.hidden=true;
        }
    }catch(e){
        grid.innerHTML=`<div class="tr-error"><i class="fas fa-circle-exclamation"></i> Couldn't load prayer times right now.</div>`;
        banner.hidden=true;
    }
}
document.getElementById('prayerRefreshBtn')?.addEventListener('click', loadPrayerTimes);
document.getElementById('prayerCitySelect')?.addEventListener('change', loadPrayerTimes);
wireSegmentedControl(document.getElementById('prayerCountryToggle'),'country',(v)=>{
    prayerCountry=v; populatePrayerCitySelect(); loadPrayerTimes();
});
populatePrayerCitySelect();
loadPrayerTimes();
setInterval(()=>{ if(document.getElementById('section-overview')?.classList.contains('active')) loadPrayerTimes(); }, 5*60*1000);

// ╔══════════════════════════════════════════════════════════╗
// ║  SERVER / VPS NAME — owner sets it once, everyone sees it     ║
// ╚══════════════════════════════════════════════════════════╝
async function loadServerName(){
    try{
        const r=await fetch('/api/settings/server-name');
        if(!r.ok)return;
        const d=await r.json();
        const name=(d.name||d.server_name||'').trim();
        const card=document.getElementById('serverNameDisplayCard');
        const val=document.getElementById('serverNameDisplayValue');
        if(card&&val){
            if(name){ val.textContent=name; card.hidden=false; }
            else{ card.hidden=true; }
        }
        const ownerInput=document.getElementById('ownerServerNameInput');
        if(ownerInput && document.activeElement!==ownerInput && !ownerInput.value) ownerInput.value=name;
    }catch(e){}
}
document.getElementById('ownerServerNameSaveBtn')?.addEventListener('click', async()=>{
    const name=document.getElementById('ownerServerNameInput').value.trim();
    const status=document.getElementById('ownerServerNameStatus');
    try{
        const r=await fetch('/api/settings/server-name',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
        if(!r.ok)throw new Error('save failed ('+r.status+')');
        status.textContent = name ? 'Saved — now visible to everyone under Preferences.' : 'Cleared — the field is now hidden for everyone.';
        status.style.color='var(--green)';
        showToast('Server name updated.');
        loadServerName();
    }catch(e){
        status.textContent='Could not save: '+e.message;
        status.style.color='var(--red-500)';
    }
});
loadServerName();

// ╔══════════════════════════════════════════════════════════╗
// ║  PANEL MANAGER (owner only) — servers using your API keys   ║
// ╚══════════════════════════════════════════════════════════╝
async function loadPanelManager(){
    const tbody=document.getElementById('panelManagerBody');
    if(!tbody)return;
    tbody.innerHTML='<tr><td colspan="5" data-i18n="loading">Loading...</td></tr>';
    try{
        const r=await fetch('/api/settings/servers');
        if(!r.ok)throw new Error(String(r.status));
        const raw=await r.json();
        const list=Array.isArray(raw)?raw:(raw.servers||[]);
        if(!list.length){
            tbody.innerHTML=`<tr><td colspan="5"><div class="empty-state">${emptyCrest}<strong>No servers yet</strong><span class="hint">Servers that call your API keys will show up here.</span></div></td></tr>`;
            return;
        }
        tbody.innerHTML=list.map(s=>`<tr>
            <td>${escapeHtml(s.server_name||s.name||'--')}</td>
            <td style="font-family:var(--font-mono);color:var(--text-primary);">${escapeHtml(s.key_prefix||s.prefix||'--')}</td>
            <td style="font-family:var(--font-mono);">${escapeHtml(s.ip||'--')}</td>
            <td>${escapeHtml(s.last_seen||'--')}</td>
            <td>${escapeHtml(String(s.requests??'--'))}</td>
        </tr>`).join('');
    }catch(e){
        tbody.innerHTML=`<tr><td colspan="5">Could not load Panel Manager data.</td></tr>`;
    }
}
document.getElementById('pmRefreshBtn')?.addEventListener('click', loadPanelManager);
window.addEventListener('section-change',(e)=>{ if(e.detail==='panelmanager')loadPanelManager(); });

// ╔══════════════════════════════════════════════════════════╗
// ║  GLOBAL CHAT — everyone signed in shares one conversation    ║
// ║  Backend contract expected:                                    ║
// ║    GET  /api/chat/messages -> { messages:[{id,username,role,  ║
// ║           text,avatar_url,timestamp}], locked:bool }          ║
// ║    POST /api/chat/send     { text } -> 200 ok / 423 if locked  ║
// ║    POST /api/chat/lock     { locked:bool }  (owner only)       ║
// ╚══════════════════════════════════════════════════════════╝
const gcMessagesEl=document.getElementById('gcMessages');
const gcPill=document.getElementById('gcConnectionPill');
const gcPillText=document.getElementById('gcConnectionText');
const gcLockedBanner=document.getElementById('gcLockedBanner');
const gcInputForm=document.getElementById('gcInputForm');
const gcMessageInput=document.getElementById('gcMessageInput');
const gcSendBtn=document.getElementById('gcSendBtn');
const gcLockToggleBtn=document.getElementById('gcLockToggleBtn');
const gcLockToggleText=document.getElementById('gcLockToggleText');
const navChatBadge=document.getElementById('navChatBadge');

let gcKnownIds=new Set();
let gcUnread=0;
let gcLocked=false;
let gcFirstLoad=true;

function setGcConnectionState(state){
    gcPill.classList.remove('connecting','connected','error');
    gcPill.classList.add(state);
    gcPillText.textContent = state==='connected' ? 'Connected' : (state==='error' ? 'Reconnecting…' : 'Connecting…');
}
function renderGcMessage(m){
    if(m.is_system || m.type==='system'){
        return `<div class="gc-msg system"><div class="gc-msg-text">${escapeHtml(m.text||'')}</div></div>`;
    }
    const isSelf = !!(m.username && currentUsername && m.username===currentUsername);
    const initial=(m.username||'?').trim().charAt(0).toUpperCase()||'?';
    const avatarInner = m.avatar_url ? `<img src="${escapeHtml(m.avatar_url)}" alt="">` : initial;
    const time = m.timestamp ? new Date(m.timestamp).toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'}) : '';
    return `<div class="gc-msg ${isSelf?'self':''}" data-username="${escapeHtml(m.username||'')}" data-role="${escapeHtml(m.role||'')}" data-avatar="${escapeHtml(m.avatar_url||'')}">
        <div class="gc-msg-avatar gc-open-profile">${avatarInner}</div>
        <div class="gc-msg-body">
            <div class="gc-msg-meta"><span class="gc-msg-name gc-open-profile">${escapeHtml(m.username||'Unknown')}</span><span class="gc-msg-role">${escapeHtml(m.role||'')}</span><span class="gc-msg-time">${time}</span></div>
            <div class="gc-msg-text">${escapeHtml(m.text||'')}</div>
        </div>
    </div>`;
}
function scrollChatToBottom(){ gcMessagesEl.scrollTop=gcMessagesEl.scrollHeight; }
function updateLockUi(){
    const ownerHere = currentUserRole==='owner';
    gcLockedBanner.hidden = !gcLocked || ownerHere;
    const canType = !gcLocked || ownerHere;
    gcMessageInput.disabled=!canType;
    gcSendBtn.disabled=!canType;
    if(ownerHere){
        gcLockToggleText.textContent = gcLocked ? 'Unlock Chat' : 'Lock Chat';
        const ic=gcLockToggleBtn.querySelector('i'); if(ic)ic.className = gcLocked ? 'fas fa-lock-open' : 'fas fa-lock';
    }
}
function updateChatBadge(){
    if(!navChatBadge)return;
    if(gcUnread>0){ navChatBadge.hidden=false; navChatBadge.textContent = gcUnread>9?'9+':String(gcUnread); }
    else{ navChatBadge.hidden=true; }
}
async function pollChat(){
    try{
        const r=await fetch('/api/chat/messages');
        if(!r.ok)throw new Error(String(r.status));
        const d=await r.json();
        const list=Array.isArray(d)?d:(d.messages||[]);
        gcLocked=!!d.locked;
        setGcConnectionState('connected');
        updateLockUi();
        if(gcFirstLoad){
            gcMessagesEl.innerHTML = list.length ? list.map(renderGcMessage).join('') : `<div class="empty-state"><strong>No messages yet</strong><span class="hint">Say hello to get things started.</span></div>`;
            list.forEach(m=>gcKnownIds.add(m.id ?? JSON.stringify(m)));
            gcFirstLoad=false;
            scrollChatToBottom();
        }else{
            let appended=false;
            const onChatSection=document.getElementById('section-globalchat')?.classList.contains('active');
            list.forEach(m=>{
                const key=m.id ?? JSON.stringify(m);
                if(!gcKnownIds.has(key)){
                    gcKnownIds.add(key);
                    if(gcMessagesEl.querySelector('.empty-state'))gcMessagesEl.innerHTML='';
                    gcMessagesEl.insertAdjacentHTML('beforeend', renderGcMessage(m));
                    appended=true;
                    if(!onChatSection && !(m.username && m.username===currentUsername)){ gcUnread++; updateChatBadge(); }
                }
            });
            if(appended)scrollChatToBottom();
        }
    }catch(e){
        setGcConnectionState('error');
    }
}
gcInputForm.addEventListener('submit', async(e)=>{
    e.preventDefault();
    const text=gcMessageInput.value.trim();
    if(!text)return;
    gcSendBtn.disabled=true;
    try{
        const r=await fetch('/api/chat/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
        if(r.status===423 || r.status===403){ showToast('Chat is locked by the Owner.','error'); }
        else if(!r.ok){ throw new Error(String(r.status)); }
        else{ gcMessageInput.value=''; pollChat(); }
    }catch(err){
        showToast('Could not send message.','error');
    }finally{
        updateLockUi();
    }
});
gcLockToggleBtn?.addEventListener('click', async()=>{
    try{
        const r=await fetch('/api/chat/lock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({locked:!gcLocked})});
        if(!r.ok)throw new Error(String(r.status));
        showToast(gcLocked ? 'Chat unlocked.' : 'Chat locked.');
        pollChat();
    }catch(err){
        showToast('Could not update lock state.','error');
    }
});
gcMessagesEl.addEventListener('click',(e)=>{
    const trigger=e.target.closest('.gc-open-profile');
    if(!trigger)return;
    const msgEl=trigger.closest('.gc-msg');
    if(!msgEl)return;
    openGcProfilePopover(msgEl.dataset.username, msgEl.dataset.role, msgEl.dataset.avatar);
});
function openGcProfilePopover(username,role,avatar){
    document.getElementById('gcPopoverName').textContent=username||'--';
    document.getElementById('gcPopoverRole').innerHTML=`<i class="fas fa-shield-halved"></i> ${escapeHtml(role||'--')}`;
    const av=document.getElementById('gcPopoverAvatar');
    av.innerHTML = avatar ? `<img src="${escapeHtml(avatar)}" alt="">` : ((username||'?').trim().charAt(0).toUpperCase());
    document.getElementById('gcProfilePopoverOverlay').hidden=false;
}
document.getElementById('gcPopoverClose').addEventListener('click',()=>{ document.getElementById('gcProfilePopoverOverlay').hidden=true; });
document.getElementById('gcProfilePopoverOverlay').addEventListener('click',(e)=>{ if(e.target.id==='gcProfilePopoverOverlay')document.getElementById('gcProfilePopoverOverlay').hidden=true; });

setGcConnectionState('connecting');
pollChat();
setInterval(()=>{ if(!document.hidden)pollChat(); }, 3000);
window.addEventListener('section-change',(e)=>{
    if(e.detail==='globalchat'){ gcUnread=0; updateChatBadge(); setTimeout(scrollChatToBottom,50); }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  PROFILE PHOTO — upload from gallery or paste an image URL  ║
// ║  POST /api/profile/photo  { image_base64 } | { url } |        ║
// ║                          { remove:true }                      ║
// ╚══════════════════════════════════════════════════════════╝
const profilePhotoModal=document.getElementById('profilePhotoModal');
const profilePhotoFileInput=document.getElementById('profilePhotoFileInput');
document.getElementById('profileAvatarEditBtn')?.addEventListener('click', ()=>{ profilePhotoModal.hidden=false; });
document.getElementById('closeProfilePhotoModal')?.addEventListener('click', ()=>{ profilePhotoModal.hidden=true; });
profilePhotoModal?.addEventListener('click',(e)=>{ if(e.target===profilePhotoModal)profilePhotoModal.hidden=true; });
document.getElementById('ppChooseUploadBtn')?.addEventListener('click', ()=>profilePhotoFileInput.click());

async function saveProfilePhoto(payload){
    const r=await fetch('/api/profile/photo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    if(!r.ok)throw new Error('Save failed ('+r.status+')');
    return r.json().catch(()=>({}));
}
profilePhotoFileInput?.addEventListener('change', async()=>{
    const file=profilePhotoFileInput.files?.[0];
    if(!file)return;
    if(file.size>5*1024*1024){ showToast('Image is too large (max 5MB).','error'); return; }
    try{
        const dataUrl=await new Promise((res,rej)=>{
            const fr=new FileReader();
            fr.onload=()=>res(fr.result);
            fr.onerror=rej;
            fr.readAsDataURL(file);
        });
        await saveProfilePhoto({image_base64:dataUrl});
        currentAvatarUrl=dataUrl;
        applyAvatarEverywhere(dataUrl, (currentUsername||'?').charAt(0).toUpperCase());
        profilePhotoModal.hidden=true;
        showToast('Profile photo updated.');
    }catch(e){
        showToast('Could not upload photo: '+e.message,'error');
    }finally{
        profilePhotoFileInput.value='';
    }
});
document.getElementById('ppUseLinkBtn')?.addEventListener('click', async()=>{
    const url=document.getElementById('ppLinkInput').value.trim();
    if(!url){ showToast('Paste an image URL first.','error'); return; }
    try{
        await saveProfilePhoto({url});
        currentAvatarUrl=url;
        applyAvatarEverywhere(url, (currentUsername||'?').charAt(0).toUpperCase());
        profilePhotoModal.hidden=true;
        showToast('Profile photo updated.');
    }catch(e){
        showToast('Could not save photo: '+e.message,'error');
    }
});
document.getElementById('ppRemoveBtn')?.addEventListener('click', async()=>{
    try{
        await saveProfilePhoto({remove:true});
        currentAvatarUrl=null;
        applyAvatarEverywhere(null, (currentUsername||'?').charAt(0).toUpperCase());
        profilePhotoModal.hidden=true;
        showToast('Profile photo removed.');
    }catch(e){
        showToast('Could not remove photo: '+e.message,'error');
    }
});

// ╔══════════════════════════════════════════════════════════╗
// ║  DEVICE & DISPLAY — battery, user agent, force UI mode       ║
// ╚══════════════════════════════════════════════════════════╝
function detectDeviceLabel(){
    const ua=navigator.userAgent;
    if(/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints>1))return {label:'Tablet (iPad)', icon:'fa-tablet-screen-button'};
    if(/iPhone|Android.*Mobile|Mobi/.test(ua))return {label:'Phone', icon:'fa-mobile-screen-button'};
    if(/Android/.test(ua))return {label:'Tablet (Android)', icon:'fa-tablet-screen-button'};
    if(/Macintosh|Mac OS X/.test(ua))return {label:'Mac', icon:'fa-laptop'};
    if(/Windows/.test(ua))return {label:'Windows PC', icon:'fa-laptop'};
    if(/Linux/.test(ua))return {label:'Linux PC', icon:'fa-laptop'};
    return {label:'Desktop', icon:'fa-desktop'};
}
function initDeviceDisplayPanel(){
    const {label,icon}=detectDeviceLabel();
    const detectedEl=document.getElementById('deviceDetectedValue');
    const detectedIcon=document.getElementById('deviceDetectedIcon');
    if(detectedEl)detectedEl.textContent=label;
    if(detectedIcon)detectedIcon.className='fas '+icon;
    const uaEl=document.getElementById('uaStringValue');
    if(uaEl)uaEl.textContent=navigator.userAgent;

    const battEl=document.getElementById('deviceBatteryValue');
    const battIcon=document.getElementById('deviceBatteryIcon');
    if(navigator.getBattery){
        navigator.getBattery().then(battery=>{
            const update=()=>{
                if(!battEl)return;
                battEl.textContent = `${Math.round(battery.level*100)}%${battery.charging?' (charging)':''}`;
                if(battIcon)battIcon.className='fas '+(battery.charging?'fa-battery-full fa-bolt':'fa-battery-half');
            };
            update();
            battery.addEventListener('levelchange', update);
            battery.addEventListener('chargingchange', update);
        }).catch(()=>{ if(battEl)battEl.textContent='Not available'; });
    }else{
        if(battEl)battEl.textContent='Not available in this browser';
    }
}
function applyUiMode(mode){
    document.body.classList.remove('force-ui-mobile','force-ui-desktop');
    if(mode==='mobile')document.body.classList.add('force-ui-mobile');
    else if(mode==='desktop')document.body.classList.add('force-ui-desktop');
    document.querySelectorAll('.ui-mode-choice').forEach(b=>b.classList.toggle('active', b.dataset.mode===mode));
    localStorage.setItem('emergens-ui-mode', mode);
}
document.getElementById('uiModeAuto')?.addEventListener('click', ()=>applyUiMode('auto'));
document.getElementById('uiModeMobile')?.addEventListener('click', ()=>applyUiMode('mobile'));
document.getElementById('uiModeDesktop')?.addEventListener('click', ()=>applyUiMode('desktop'));
applyUiMode(localStorage.getItem('emergens-ui-mode')||'auto');
initDeviceDisplayPanel();

// ╔══════════════════════════════════════════════════════════╗
// ║  SECURITY TESTING — briefing video (fill in the URL below)  ║
// ╚══════════════════════════════════════════════════════════╝
const SECURITY_BRIEFING_VIDEO_URL = 'https://v1.pinimg.com/videos/iht/expMp4/fe/e7/69/fee769ca6b98455767b4de462393581c_720w.mp4';
(function initBriefingVideo(){
    const wrap=document.getElementById('briefingVideoWrap');
    const placeholder=document.getElementById('briefingVideoPlaceholder');
    const video=document.getElementById('briefingVideo');
    if(!wrap)return;
    if(SECURITY_BRIEFING_VIDEO_URL){
        video.src=SECURITY_BRIEFING_VIDEO_URL;
        video.hidden=false;
        placeholder.hidden=true;
        video.loop=true;
        video.muted=true;
        const keepPlaying=()=>{ video.play().catch(()=>{}); };
        video.addEventListener('loadedmetadata', keepPlaying);
        video.addEventListener('pause', keepPlaying);   // can't be paused — resumes immediately
        video.addEventListener('ended', keepPlaying);    // belt-and-braces alongside native loop
        video.addEventListener('contextmenu', e=>e.preventDefault());
        video.addEventListener('keydown', e=>e.preventDefault());
        keepPlaying();
    }else{
        video.hidden=true;
        placeholder.hidden=false;
    }
})();
// ═══════════════════════════════════════════════════════════
//  SIDEBAR MOBILE TOGGLE + OVERLAY
// ═══════════════════════════════════════════════════════════
(function(){
    const sidebar  = document.getElementById('sidebar');
    const overlay  = document.getElementById('sidebarOverlay');
    const closeBtn = document.getElementById('sidebarCloseBtn');
    const hamburger = document.getElementById('headerHamburger');   // optional

    function openSidebar(){
        sidebar.classList.add('mobile-open');
        overlay.classList.add('visible');
        document.body.style.overflow = 'hidden';
    }
    function closeSidebar(){
        sidebar.classList.remove('mobile-open');
        overlay.classList.remove('visible');
        document.body.style.overflow = '';
    }
    if(overlay)  overlay.addEventListener('click', closeSidebar);
    if(closeBtn) closeBtn.addEventListener('click', closeSidebar);
    if(hamburger) hamburger.addEventListener('click', openSidebar);

    // Close on nav-item click (mobile)
    sidebar.querySelectorAll('.nav-item[data-section]').forEach(btn=>{
        btn.addEventListener('click', ()=>{
            if(window.innerWidth <= 860) closeSidebar();
        });
    });
    // Keyboard: Escape closes
    document.addEventListener('keydown', e=>{
        if(e.key==='Escape' && sidebar.classList.contains('mobile-open')) closeSidebar();
    });
    // Swipe-to-close: track touch start on the overlay
    let tsX = 0;
    overlay.addEventListener('touchstart', e=>{ tsX = e.touches[0].clientX; }, {passive:true});
    overlay.addEventListener('touchend', e=>{
        if(tsX - e.changedTouches[0].clientX > 40) closeSidebar();
    }, {passive:true});
})();

// ═══════════════════════════════════════════════════════════
//  NETWORK TRAFFIC — animated SVG spark-line upgrade
// ═══════════════════════════════════════════════════════════
(function(){
    const NT_POINTS = 24;
    const inHistory  = Array(NT_POINTS).fill(0);
    const outHistory = Array(NT_POINTS).fill(0);

    function polyFromHistory(hist, w, h){
        const max = Math.max(1, ...hist);
        const pts = hist.map((v, i) => {
            const x = (i / (hist.length - 1)) * w;
            const y = h - (v / max) * (h * 0.85);
            return `${x.toFixed(1)},${y.toFixed(1)}`;
        });
        const area = `${pts.join(' ')} ${w},${h} 0,${h}`;
        return { line: pts.join(' '), area };
    }

    function renderSparkSVG(containerId, hist, gradId){
        const el = document.getElementById(containerId);
        if(!el) return;
        const W = el.clientWidth || 260, H = 52;
        const { line, area } = polyFromHistory(hist, W, H);
        el.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
            <defs>
                <linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="currentColor" stop-opacity="0.35"/>
                    <stop offset="100%" stop-color="currentColor" stop-opacity="0"/>
                </linearGradient>
            </defs>
            <polygon class="nt-area" points="${area}" fill="url(#${gradId})" opacity="0.9"/>
            <polyline class="nt-line" points="${line}" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
            <circle class="nt-dot" cx="${W}" cy="${(function(){const max=Math.max(1,...hist);return H-(hist[hist.length-1]/max)*(H*0.85);}())}" r="3.5" fill="currentColor"/>
        </svg>`;
    }

    const ORIG_REFRESH = window.refreshNetworkTraffic;
    window.refreshNetworkTraffic = async function(){
        try{
            const url = '/api/network/traffic';
            const r   = await fetch(url);
            if(!r.ok) throw new Error(r.status);
            const d = await r.json();

            const bytesIn  = d.bytes_recv  || d.inbound  || d.received || 0;
            const bytesOut = d.bytes_sent  || d.outbound || d.sent     || 0;

            inHistory.push(bytesIn);  if(inHistory.length  > NT_POINTS) inHistory.shift();
            outHistory.push(bytesOut);if(outHistory.length > NT_POINTS) outHistory.shift();

            // Value labels
            function fmtBytes(b){ if(b>=1e9) return (b/1e9).toFixed(1)+' GB'; if(b>=1e6) return (b/1e6).toFixed(1)+' MB'; if(b>=1e3) return (b/1e3).toFixed(1)+' KB'; return b+' B'; }
            const elIn  = document.getElementById('netInboundVal')  || document.getElementById('nttInbound')  || document.querySelector('[data-net="in"]');
            const elOut = document.getElementById('netOutboundVal') || document.getElementById('nttOutbound') || document.querySelector('[data-net="out"]');
            if(elIn)  elIn.textContent  = fmtBytes(bytesIn);
            if(elOut) elOut.textContent = fmtBytes(bytesOut);

            renderSparkSVG('netInboundSpark',  inHistory,  'ntGradIn');
            renderSparkSVG('netOutboundSpark', outHistory, 'ntGradOut');
        }catch(e){
            // silently ignore — the overview still shows 0/0 fallback text
        }
    };

    // Kick off initial render immediately with zeros to paint the axes
    renderSparkSVG('netInboundSpark',  inHistory,  'ntGradIn');
    renderSparkSVG('netOutboundSpark', outHistory, 'ntGradOut');
})();

// ═══════════════════════════════════════════════════════════
//  SIDEBAR CUSTOMISER (Preferences section)
// ═══════════════════════════════════════════════════════════
(function(){
    const PREFS_KEY = 'em_sidebar_prefs';
    function loadSbPrefs(){
        try{ return JSON.parse(localStorage.getItem(PREFS_KEY)||'{}'); }catch(e){ return {}; }
    }
    function saveSbPrefs(p){ localStorage.setItem(PREFS_KEY, JSON.stringify(p)); }
    function applyPrefs(p){
        const root = document.documentElement;
        if(p.color){ root.style.setProperty('--accent', p.color); root.style.setProperty('--accent2', p.color); }
        if(p.style){ root.setAttribute('data-sidebar-style', p.style); }
        if(p.labels === false) root.setAttribute('data-sidebar-hidden-labels','1');
        else root.removeAttribute('data-sidebar-hidden-labels');
    }

    // Apply on load
    applyPrefs(loadSbPrefs());

    // Swatches
    const swatchWrap = document.getElementById('sbColorSwatches');
    if(swatchWrap) swatchWrap.addEventListener('click', e=>{
        const s = e.target.closest('.sb-swatch');
        if(!s) return;
        swatchWrap.querySelectorAll('.sb-swatch').forEach(x=>x.classList.remove('active'));
        s.classList.add('active');
        const p = loadSbPrefs(); p.color = s.dataset.color; saveSbPrefs(p); applyPrefs(p);
        showToast('Accent colour updated');
    });

    // Style buttons
    const styleWrap = document.getElementById('sbStyleBtns');
    if(styleWrap) styleWrap.addEventListener('click', e=>{
        const b = e.target.closest('.sb-style-btn');
        if(!b) return;
        styleWrap.querySelectorAll('.sb-style-btn').forEach(x=>x.classList.remove('active'));
        b.classList.add('active');
        const p = loadSbPrefs(); p.style = b.dataset.style; saveSbPrefs(p); applyPrefs(p);
        showToast('Sidebar style updated');
    });

    // Labels toggle
    const labelsToggle = document.getElementById('sbShowLabels');
    if(labelsToggle){
        const p = loadSbPrefs();
        labelsToggle.checked = p.labels !== false;
        labelsToggle.addEventListener('change', ()=>{
            const p2 = loadSbPrefs(); p2.labels = labelsToggle.checked; saveSbPrefs(p2); applyPrefs(p2);
        });
    }

    // Sync swatches/style to saved prefs visually
    const p0 = loadSbPrefs();
    if(p0.color && swatchWrap){
        swatchWrap.querySelectorAll('.sb-swatch').forEach(s=>{
            s.classList.toggle('active', s.dataset.color===p0.color);
        });
    }
    if(p0.style && styleWrap){
        styleWrap.querySelectorAll('.sb-style-btn').forEach(b=>{
            b.classList.toggle('active', b.dataset.style===p0.style);
        });
    }
})();

// ═══════════════════════════════════════════════════════════
//  NAV TRANSLATION STRINGS — new keys
// ═══════════════════════════════════════════════════════════
(function(){
    // Patch the translation table without touching the original i18n init
    const extras_en = {
        nav_assets:'Assets', nav_status:'Status',
        assets_title:'Assets & Scan History', assets_filter_ph:'Filter by target…',
        prefs_sidebar_title:'Sidebar / Menu Appearance', prefs_sidebar_desc:'Customize sidebar accent, glass effect, and label visibility.',
        testing_select_tools:'Swipe to browse & select tools to run:',
    };
    const extras_ms = {
        nav_assets:'Aset', nav_status:'Status',
        assets_title:'Aset & Sejarah Imbasan',
        prefs_sidebar_title:'Rupa Sidebar / Menu', prefs_sidebar_desc:'Sesuaikan aksen sidebar, kesan kaca, dan keterlihatan label.',
        testing_select_tools:'Leret untuk semak & pilih alat yang hendak dijalankan:',
    };
    function patchStrings(lang, extras){
        if(window.STRINGS && window.STRINGS[lang]) Object.assign(window.STRINGS[lang], extras);
    }
    // Run after DOM ready / i18n loaded
    setTimeout(()=>{ patchStrings('en', extras_en); patchStrings('ms', extras_ms); }, 50);
})();