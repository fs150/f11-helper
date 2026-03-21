/**
 * Daly Alpha - Main Application
 * A production-ready gaming troop calculator
 * 
 * Architecture:
 * - DalyApp: Main application controller
 * - Modules: Storage, Translations, Calculator, OCR, UI, History
 */

'use strict';

// ============================================
// STORAGE MODULE
// ============================================
const Storage = {
  get(key, defaultValue = null) {
    try {
      const value = localStorage.getItem(key);
      return value !== null ? value : defaultValue;
    } catch (e) {
      console.warn('Storage.get failed:', e);
      return defaultValue;
    }
  },
  
  set(key, value) {
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
      console.warn('Storage.set failed:', e);
      return false;
    }
  },
  
  getJSON(key, defaultValue = null) {
    try {
      const value = this.get(key);
      return value ? JSON.parse(value) : defaultValue;
    } catch (e) {
      return defaultValue;
    }
  },
  
  setJSON(key, value) {
    return this.set(key, JSON.stringify(value));
  },
  
  remove(key) {
    try {
      localStorage.removeItem(key);
    } catch (e) {}
  }
};

// ============================================
// TRANSLATIONS MODULE
// ============================================
const Translations = {
  ar: {
    // General
    title: "Daly",
    tagline: "مساعدك الذكي لحساب التشكيلة المثالية",
    hintPrefix: "أدخل الأرقام مثل:",
    dark: "داكن",
    light: "فاتح",
    
    // Onboarding
    onboardingTitle: "مرحباً بك في Daly Alpha!",
    onboardingText: "ارفع صورة تقرير الاستطلاع أو أدخل الأرقام يدوياً وسنحسب لك أفضل تشكيلة للهجوم",
    onboardingDismiss: "فهمت",
    
    // Ticker
    tickerBadge: "جديد",
    tickerMsg: "نصيحة: ارفع صورة تقرير الاستطلاع ليتم تعبئة الأرقام تلقائياً",
    
    // Upload
    uploadLabel: "صورة تقرير الاستطلاع",
    uploadGallery: "المعرض",
    uploadGallerySub: "اختر صورة من جهازك",
    uploadSelect: "تحميل صورة",
    uploadReplace: "استبدال",
    uploadRemove: "إزالة",
    uploadStatusReady: "جاهز للقراءة",
    uploadStatusReading: "جاري القراءة...",
    uploadStatusDone: "تمت القراءة",
    uploadStatusError: "تعذر القراءة",
    
    // Inputs
    sni: "قناص",
    inf: "مقاتل",
    cav: "جوال",
    placeholder: "مثال: 360k",
    validFormat: "صيغة صحيحة",
    invalidFormat: "صيغة غير صحيحة",
    clear: "مسح",
    
    // Camps
    campsTitle: "المعسكرات المحفوظة",
    campsSub: "احفظ وحمّل الأرقام بنقرة",
    campNamePh: "اسم المعسكر...",
    campSave: "حفظ",
    campLoad: "تحميل",
    campNoName: "أدخل اسم المعسكر",
    campNoTroops: "أدخل أرقام القوات أولاً",
    campSaved: "تم الحفظ!",
    campUpdated: "تم التحديث",
    campsEmpty: "لا توجد معسكرات محفوظة",
    
    // Actions
    btnCalc: "احسب أفضل تشكيلة",
    btnSmart: "تحليل ذكي",
    btnCopy: "نسخ",
    btnShare: "مشاركة",
    btnReset: "إعادة ضبط",
    btnDownload: "تحميل",
    
    // Output
    outputIdle: "أدخل قوات العدو واضغط الزر",
    outputIdleIcon: "⚔️",
    error: "أدخل قوات العدو أولاً",
    resultTitle: "التوصية",
    enemyTroops: "قوات العدو",
    recommendation: "أفضل تشكيلة للهجوم",
    copyInline: "نسخ",
    copied: "تم النسخ!",
    shared: "تم إنشاء الرابط!",
    
    // Reason
    reason1: "السبب:",
    reason2: "أكبر نوع عند العدو هو",
    reason3: "وأفضل مضاد له هو",
    reason4: "نضيف",
    reason5: "لتغطية النوع الذي يهدد",
    
    // Smart Analysis
    smartTitle: "التحليل الذكي",
    smartSub: "نظرة متعمقة للحصول على أفضل النتائج",
    smartEnemy: "توزيع قوات العدو",
    smartRec: "التوصية الذكية",
    smartWhy: "لماذا هذا الاختيار؟",
    smartWhy1: "هو أفضل مضاد لـ",
    smartWhy2: "العدو يمتلك نسبة من",
    smartWhy3: "لذا نضيف",
    smartWhy4: "لا توجد تهديدات ثانوية كبيرة",
    smartWhy5: "النسبة المثالية المحسوبة هي",
    smartNote: "هذه النسب مبنية على تحليل رياضي لتقليل خسائرك",
    
    // Chart
    ratioHint: "النسبة المثالية",
    legendTitle: "التوصية",
    
    // History
    historyTitle: "السجل",
    historyClear: "مسح الكل",
    historyEmpty: "لا يوجد سجل بعد",
    
    // Footer
    footerText: "تم إنشاء هذا المساعد بواسطة",
    
    // Confirm Dialog
    confirmResetTitle: "إعادة ضبط؟",
    confirmResetMsg: "سيتم مسح جميع الحقول",
    confirmCancel: "إلغاء",
    confirmOk: "نعم، امسح",
    
    confirmDeleteCampTitle: "حذف المعسكر؟",
    confirmDeleteCampMsg: "لا يمكن التراجع عن هذا الإجراء",
    
    // Toast
    toastReset: "تمت إعادة الضبط",
    toastNeed: "أدخل قوات العدو أولاً",
    toastError: "حدث خطأ",
    
    // OCR
    loadingText: "جاري تحليل الصورة...",
    ocrFail: "لم يتم التعرف على الأرقام. تأكد أن الصورة واضحة."
  },
  
  en: {
    title: "Daly",
    tagline: "Your smart troop composition calculator",
    hintPrefix: "Enter numbers like:",
    dark: "Dark",
    light: "Light",
    
    onboardingTitle: "Welcome to Daly Alpha!",
    onboardingText: "Upload a scout report screenshot or enter the numbers manually and we'll calculate the best attack composition",
    onboardingDismiss: "Got it",
    
    tickerBadge: "NEW",
    tickerMsg: "Tip: Upload a scout report screenshot to auto-fill troop totals",
    
    uploadLabel: "Scout Report Image",
    uploadGallery: "Gallery",
    uploadGallerySub: "Choose a scout report image",
    uploadSelect: "Upload Image",
    uploadReplace: "Replace",
    uploadRemove: "Remove",
    uploadStatusReady: "Ready to read",
    uploadStatusReading: "Reading...",
    uploadStatusDone: "Read successfully",
    uploadStatusError: "Could not read",
    
    sni: "Snipers",
    inf: "Fighters",
    cav: "Cavalry",
    placeholder: "e.g. 360k",
    validFormat: "Valid format",
    invalidFormat: "Invalid format",
    clear: "Clear",
    
    campsTitle: "Saved Camps",
    campsSub: "Save & load numbers instantly",
    campNamePh: "Camp name...",
    campSave: "Save",
    campLoad: "Load",
    campNoName: "Enter a camp name",
    campNoTroops: "Enter troop numbers first",
    campSaved: "Saved!",
    campUpdated: "Updated",
    campsEmpty: "No saved camps yet",
    
    btnCalc: "Calculate Best Composition",
    btnSmart: "Smart Analysis",
    btnCopy: "Copy",
    btnShare: "Share",
    btnReset: "Reset",
    btnDownload: "Download",

    outputIdle: "Enter enemy troops and press the button",
    outputIdleIcon: "⚔️",
    error: "Enter enemy troops first",
    resultTitle: "Recommendation",
    enemyTroops: "Enemy Troops",
    recommendation: "Best Attack Composition",
    copyInline: "Copy",
    copied: "Copied!",
    shared: "Link ready!",
    
    reason1: "Reason:",
    reason2: "The largest enemy type is",
    reason3: "Best counter is",
    reason4: "We add",
    reason5: "to cover the type that threatens",
    
    smartTitle: "Smart Analysis",
    smartSub: "In-depth look for best results",
    smartEnemy: "Enemy Troop Distribution",
    smartRec: "Smart Recommendation",
    smartWhy: "Why this choice?",
    smartWhy1: "is the best counter to",
    smartWhy2: "The enemy has a portion of",
    smartWhy3: "so we add",
    smartWhy4: "No major secondary threats",
    smartWhy5: "The ideal calculated ratio is",
    smartNote: "These ratios are based on mathematical analysis to minimize your losses",
    
    ratioHint: "Ideal Ratio",
    legendTitle: "Recommendation",
    
    historyTitle: "History",
    historyClear: "Clear All",
    historyEmpty: "No history yet",
    
    footerText: "This helper was created by",
    
    confirmResetTitle: "Reset?",
    confirmResetMsg: "All fields will be cleared",
    confirmCancel: "Cancel",
    confirmOk: "Yes, clear",
    
    confirmDeleteCampTitle: "Delete camp?",
    confirmDeleteCampMsg: "This action cannot be undone",
    
    toastReset: "Reset complete",
    toastNeed: "Enter enemy troops first",
    toastError: "An error occurred",
    
    loadingText: "Analyzing image...",
    ocrFail: "Could not read numbers. Make sure the image is clear."
  },
  
  pt: {
    title: "Daly",
    tagline: "Seu calculador inteligente de composição de tropas",
    hintPrefix: "Digite números como:",
    dark: "Escuro",
    light: "Claro",
    
    onboardingTitle: "Bem-vindo ao Daly Alpha!",
    onboardingText: "Envie uma captura do relatório de exploração ou digite os números manualmente e calcularemos a melhor composição de ataque",
    onboardingDismiss: "Entendi",
    
    tickerBadge: "NOVO",
    tickerMsg: "Dica: Envie uma captura do relatório para preencher as tropas automaticamente",
    
    uploadLabel: "Imagem do Relatório",
    uploadGallery: "Galeria",
    uploadGallerySub: "Escolha uma imagem do relatório",
    uploadSelect: "Enviar Imagem",
    uploadReplace: "Trocar",
    uploadRemove: "Remover",
    uploadStatusReady: "Pronto para ler",
    uploadStatusReading: "Lendo...",
    uploadStatusDone: "Leitura concluída",
    uploadStatusError: "Não foi possível ler",
    
    sni: "Atiradores",
    inf: "Lutadores",
    cav: "Cavalaria",
    placeholder: "ex: 360k",
    validFormat: "Formato válido",
    invalidFormat: "Formato inválido",
    clear: "Limpar",
    
    campsTitle: "Acampamentos Salvos",
    campsSub: "Salve e carregue números instantaneamente",
    campNamePh: "Nome do acampamento...",
    campSave: "Salvar",
    campLoad: "Carregar",
    campNoName: "Insira um nome",
    campNoTroops: "Insira as tropas primeiro",
    campSaved: "Salvo!",
    campUpdated: "Atualizado",
    campsEmpty: "Nenhum acampamento salvo",
    
    btnCalc: "Calcular Melhor Composição",
    btnSmart: "Análise Inteligente",
    btnCopy: "Copiar",
    btnShare: "Compartilhar",
    btnReset: "Redefinir",
    btnDownload: "Baixar",

    outputIdle: "Insira as tropas inimigas e pressione o botão",
    outputIdleIcon: "⚔️",
    error: "Insira as tropas inimigas primeiro",
    resultTitle: "Recomendação",
    enemyTroops: "Tropas Inimigas",
    recommendation: "Melhor Composição de Ataque",
    copyInline: "Copiar",
    copied: "Copiado!",
    shared: "Link pronto!",
    
    reason1: "Motivo:",
    reason2: "O maior tipo inimigo é",
    reason3: "O melhor contra é",
    reason4: "Adicionamos",
    reason5: "para cobrir o tipo que ameaça",
    
    smartTitle: "Análise Inteligente",
    smartSub: "Visão aprofundada para melhores resultados",
    smartEnemy: "Distribuição de Tropas Inimigas",
    smartRec: "Recomendação Inteligente",
    smartWhy: "Por que essa escolha?",
    smartWhy1: "é o melhor contra",
    smartWhy2: "O inimigo tem uma porção de",
    smartWhy3: "então adicionamos",
    smartWhy4: "Sem grandes ameaças secundárias",
    smartWhy5: "A proporção ideal calculada é",
    smartNote: "Essas proporções são baseadas em análise matemática para minimizar suas perdas",
    
    ratioHint: "Proporção Ideal",
    legendTitle: "Recomendação",
    
    historyTitle: "Histórico",
    historyClear: "Limpar Tudo",
    historyEmpty: "Sem histórico ainda",
    
    footerText: "Este assistente foi criado por",
    
    confirmResetTitle: "Redefinir?",
    confirmResetMsg: "Todos os campos serão limpos",
    confirmCancel: "Cancelar",
    confirmOk: "Sim, limpar",
    
    confirmDeleteCampTitle: "Excluir acampamento?",
    confirmDeleteCampMsg: "Esta ação não pode ser desfeita",
    
    toastReset: "Redefinição concluída",
    toastNeed: "Insira as tropas inimigas primeiro",
    toastError: "Ocorreu um erro",
    
    loadingText: "Analisando imagem...",
    ocrFail: "Não foi possível ler os números. Certifique-se de que a imagem está clara."
  }
};

// ============================================
// CALCULATOR MODULE
// ============================================
const Calculator = {
  // Game mechanics: rock-paper-scissors counter system
  // Snipers beat Cavalry, Cavalry beat Infantry, Infantry beat Snipers
  counterOf: { sni: 'cav', inf: 'sni', cav: 'inf' },
  beatenBy: { cav: 'inf', sni: 'cav', inf: 'sni' },
  
  parseNum(value) {
    const v = String(value || '').toLowerCase().trim().replace(/,/g, '');
    if (v.endsWith('k')) return (parseFloat(v) || 0) * 1000;
    if (v.endsWith('m')) return (parseFloat(v) || 0) * 1000000;
    return parseFloat(v) || 0;
  },
  
  formatNum(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'm';
    if (num >= 1000) return (num / 1000).toFixed(0) + 'k';
    return String(num);
  },
  
  validateInput(value) {
    const v = String(value || '').trim().toLowerCase();
    if (!v) return { valid: false, empty: true };

    // Allow explicit zero (useful for OCR on reports showing 0)
    if (v === '0') return { valid: true, empty: false };
    
    // Valid patterns: 360k, 1.1m, 360.5k, 1m, 500k, etc.
    const pattern = /^\d+\.?\d*[km]$/i;
    if (pattern.test(v)) {
      return { valid: true, empty: false };
    }
    
    // Also accept plain numbers
    if (/^\d+\.?\d*$/.test(v) && parseFloat(v) >= 0) {
      return { valid: true, empty: false };
    }
    
    return { valid: false, empty: false };
  },
  
  calculate(enemy) {
    const total = enemy.sni + enemy.inf + enemy.cav;
    if (total <= 0) return null;
    
    // Find the dominant enemy troop type
    let major = 'sni';
    if (enemy.inf > enemy[major]) major = 'inf';
    if (enemy.cav > enemy[major]) major = 'cav';
    
    // Primary counter: what beats the dominant type
    const primary = this.counterOf[major];
    
    // The type that beats our primary
    const danger = this.beatenBy[primary];
    
    // Secondary counter: what beats the danger type
    const secondary = this.counterOf[danger];
    
    // Calculate ratio based on enemy composition
    const dangerRatio = enemy[danger] / total;
    
    let primaryPct;
    if (dangerRatio < 0.18) primaryPct = 80;
    else if (dangerRatio < 0.30) primaryPct = 70;
    else if (dangerRatio < 0.45) primaryPct = 65;
    else primaryPct = 60;
    
    // If secondary is same as primary, use 100%
    if (secondary === primary) primaryPct = 100;
    
    const secondaryPct = 100 - primaryPct;
    
    return {
      primary,
      secondary,
      primaryPct,
      secondaryPct,
      major,
      danger,
      total,
      enemy
    };
  },
  
  smartAnalysis(enemy) {
    const total = enemy.sni + enemy.inf + enemy.cav;
    if (total <= 0) return null;
    
    const e = [enemy.sni / total, enemy.inf / total, enemy.cav / total];
    const counter = [2, 0, 1]; // sni->cav, inf->sni, cav->inf (indices)
    const losesTo = [2, 0, 1];
    
    // Find dominant type (by index: 0=sni, 1=inf, 2=cav)
    let E1 = 0;
    for (let i = 1; i < 3; i++) if (e[i] > e[E1]) E1 = i;
    
    const P = counter[E1];      // Primary counter
    const V = losesTo[P];       // What beats primary
    const S = counter[V];       // Secondary counter
    
    const dominance = e[E1];
    const vShare = e[V];
    
    // Calculate optimal ratio
    let primaryPct = 70 + (dominance - 0.50) * 30 - vShare * 40;
    primaryPct = Math.max(55, Math.min(85, primaryPct));
    primaryPct = Math.round(primaryPct / 5) * 5;
    primaryPct = Math.max(55, Math.min(85, primaryPct));
    
    const secondaryPct = 100 - primaryPct;
    
    const typeKey = (i) => ['sni', 'inf', 'cav'][i];
    
    return {
      primary: typeKey(P),
      secondary: typeKey(S),
      primaryPct,
      secondaryPct,
      dominant: typeKey(E1),
      dominantPct: Math.round(e[E1] * 100),
      vulnerability: typeKey(V),
      vulnerabilityPct: Math.round(e[V] * 100),
      distribution: {
        sni: Math.round(e[0] * 100),
        inf: Math.round(e[1] * 100),
        cav: Math.round(e[2] * 100)
      },
      enemy,
      total
    };
  }
};

// ============================================
// HISTORY MODULE
// ============================================
const History = {
  KEY: 'F11_HISTORY',
  MAX_ITEMS: 10,
  
  getAll() {
    return Storage.getJSON(this.KEY, []);
  },
  
  add(entry) {
    const history = this.getAll();
    
    // Add timestamp
    entry.timestamp = Date.now();
    
    // Add to beginning
    history.unshift(entry);
    
    // Limit to MAX_ITEMS
    if (history.length > this.MAX_ITEMS) {
      history.pop();
    }
    
    Storage.setJSON(this.KEY, history);
  },
  
  clear() {
    Storage.setJSON(this.KEY, []);
  },
  
  formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    
    // Today
    if (date.toDateString() === now.toDateString()) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    // This week
    const diffDays = Math.floor((now - date) / (1000 * 60 * 60 * 24));
    if (diffDays < 7) {
      return date.toLocaleDateString([], { weekday: 'short' });
    }
    
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  }
};

// ============================================
// CAMPS MODULE
// ============================================
const Camps = {
  KEY: 'F11_SAVED_CAMPS',
  
  getAll() {
    return Storage.getJSON(this.KEY, []);
  },
  
  save(camp) {
    const camps = this.getAll();
    const existIdx = camps.findIndex(c => c.name === camp.name);
    
    if (existIdx >= 0) {
      camps[existIdx] = camp;
      Storage.setJSON(this.KEY, camps);
      return 'updated';
    } else {
      camps.unshift(camp);
      Storage.setJSON(this.KEY, camps);
      return 'saved';
    }
  },
  
  delete(index) {
    const camps = this.getAll();
    if (index >= 0 && index < camps.length) {
      camps.splice(index, 1);
      Storage.setJSON(this.KEY, camps);
      return true;
    }
    return false;
  },
  
  get(index) {
    const camps = this.getAll();
    return camps[index] || null;
  }
};

// ============================================
// MAIN APPLICATION
// ============================================
const DalyApp = {
  lang: 'ar',
  t: Translations.ar,
  lastResult: null,
  lastCopyText: '',
  confirmCallback: null,
  tesseractLoaded: false,
  
  // ==========================================
  // INITIALIZATION
  // ==========================================
  init() {
    // Load saved language or detect from browser
    const savedLang = Storage.get('F11_LANG');
    if (savedLang && Translations[savedLang]) {
      this.lang = savedLang;
    } else {
      const browserLang = (navigator.language || '').toLowerCase();
      if (browserLang.startsWith('pt')) this.lang = 'pt';
      else if (browserLang.startsWith('en')) this.lang = 'en';
      else this.lang = 'ar';
    }
    
    this.t = Translations[this.lang];
    
    // Load saved theme
    const savedDark = Storage.get('F11_DARK');
    if (savedDark === '1') {
      document.body.classList.add('dark');
    }
    
    // Check onboarding
    const onboardingSeen = Storage.get('F11_ONBOARDING_SEEN');
    if (onboardingSeen !== '1') {
      document.getElementById('onboarding')?.classList.remove('hidden');
    }
    
    // Check ticker
    const tickerDismissed = Storage.get('F11_TICKER_DISMISSED');
    if (tickerDismissed === '1') {
      document.getElementById('ticker')?.classList.add('hidden');
    }
    
    // Initialize UI
    this.updateLanguage();
    this.updateThemeButton();
    this.renderCamps();
    this.renderHistory();
    this.setupEventListeners();
    this.setupInputValidation();
    this.setupUploadGalleryVideo();
    
    // Register service worker
    this.registerServiceWorker();
  },
  
  registerServiceWorker() {
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('sw.js')
          .then(reg => console.log('SW registered'))
          .catch(err => console.log('SW registration skipped'));
      });
    }
  },
  
  // ==========================================
  // EVENT LISTENERS
  // ==========================================
  setupEventListeners() {
    // Language buttons
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const lang = btn.dataset.lang;
        if (lang && Translations[lang]) {
          this.setLanguage(lang);
        }
      });
    });
    
    // Theme toggle
    document.getElementById('themeToggle')?.addEventListener('click', () => {
      this.toggleTheme();
    });
    
    // Onboarding dismiss
    document.getElementById('onboardingDismiss')?.addEventListener('click', () => {
      this.dismissOnboarding();
    });
    
    // Ticker dismiss
    document.getElementById('tickerDismiss')?.addEventListener('click', () => {
      this.dismissTicker();
    });
    
    // Upload flow (single Gallery entry)
    const uploadInput = document.getElementById('uploadInput');
    const uploadCta = document.getElementById('uploadCta');
    const uploadReplaceBtn = document.getElementById('uploadReplaceBtn');
    const uploadRemoveBtn = document.getElementById('uploadRemoveBtn');

    uploadCta?.addEventListener('click', () => uploadInput?.click());
    uploadReplaceBtn?.addEventListener('click', () => uploadInput?.click());
    uploadRemoveBtn?.addEventListener('click', () => this.clearUploadPreview());
    uploadInput?.addEventListener('change', (e) => this.handleImageUpload(e));
    
    // Input clear buttons
    document.querySelectorAll('.input-clear-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const inputId = btn.dataset.input;
        const input = document.getElementById(inputId);
        if (input) {
          input.value = '';
          this.validateInput(input);
        }
      });
    });
    
    // Camps section
    document.getElementById('campsHeader')?.addEventListener('click', () => {
      document.getElementById('campsSection')?.classList.toggle('open');
    });
    
    document.getElementById('campSaveBtn')?.addEventListener('click', () => {
      this.saveCurrentCamp();
    });
    
    document.getElementById('campNameInput')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.saveCurrentCamp();
    });
    
    // Action buttons
    document.getElementById('btnCalc')?.addEventListener('click', () => {
      this.calculate();
    });
    
    document.getElementById('btnSmart')?.addEventListener('click', () => {
      this.smartAnalyze();
    });
    
    document.getElementById('btnCopy')?.addEventListener('click', () => {
      this.copyResult();
    });
    
    document.getElementById('btnShare')?.addEventListener('click', () => {
      this.shareResult();
    });
    
    document.getElementById('btnReset')?.addEventListener('click', () => {
      this.confirmReset();
    });

    // Download image button
    document.getElementById('btnDownload')?.addEventListener('click', (e) => {
      // Ripple effect
      const btn = e.currentTarget;
      const r = btn.getBoundingClientRect();
      const size = Math.max(r.width, r.height);
      const ripple = document.createElement('span');
      ripple.className = 'dl-ripple';
      ripple.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - r.left - size/2}px;top:${e.clientY - r.top - size/2}px;`;
      btn.appendChild(ripple);
      ripple.addEventListener('animationend', () => ripple.remove());
      this.downloadUploadedImage();
    });

    // Result copy button
    document.getElementById('resultCopyBtn')?.addEventListener('click', () => {
      this.copyResult();
    });
    
    // History clear
    document.getElementById('historyClearBtn')?.addEventListener('click', () => {
      History.clear();
      this.renderHistory();
      this.toast(this.t.toastReset);
    });
    
    // Confirm dialog
    document.getElementById('confirmCancel')?.addEventListener('click', () => {
      this.closeConfirm();
    });
    
    document.getElementById('confirmOk')?.addEventListener('click', () => {
      if (this.confirmCallback) {
        this.confirmCallback();
      }
      this.closeConfirm();
    });
    
    // Close confirm on overlay click
    document.getElementById('confirmOverlay')?.addEventListener('click', (e) => {
      if (e.target.id === 'confirmOverlay') {
        this.closeConfirm();
      }
    });
    
    // Keyboard shortcut: Enter to calculate
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.target.matches('input, textarea, button')) {
        this.calculate();
      }
    });
  },

  setupUploadGalleryVideo() {
    const button = document.getElementById('uploadCta');
    const video = button?.querySelector('.pg-video');
    const source = video?.querySelector('source');
    const motionQuery = typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)')
      : null;

    if (!button || !video) return;

    const syncPlayback = () => {
      if (document.hidden || motionQuery?.matches) {
        video.pause();
        return;
      }

      const playPromise = video.play();
      if (playPromise && typeof playPromise.catch === 'function') {
        playPromise.catch(() => {});
      }
    };

    const fallbackToPoster = () => {
      button.classList.add('video-fallback');
    };

    video.addEventListener('loadeddata', () => {
      button.classList.remove('video-fallback');
      syncPlayback();
    });
    video.addEventListener('error', fallbackToPoster);
    source?.addEventListener('error', fallbackToPoster);
    document.addEventListener('visibilitychange', syncPlayback);
    motionQuery?.addEventListener?.('change', syncPlayback);

    syncPlayback();
  },

  // ==========================================
  // INPUT VALIDATION
  // ==========================================
  setupInputValidation() {
    ['inputSni', 'inputInf', 'inputCav'].forEach(id => {
      const input = document.getElementById(id);
      if (input) {
        input.addEventListener('input', () => this.validateInput(input));
        input.addEventListener('blur', () => this.validateInput(input));
      }
    });
  },
  
  validateInput(input) {
    const card = input.closest('.input-card');
    const validation = card?.querySelector('.input-validation');
    
    const result = Calculator.validateInput(input.value);
    
    card?.classList.remove('valid', 'invalid');
    
    if (result.empty) {
      if (validation) validation.innerHTML = '';
    } else if (result.valid) {
      card?.classList.add('valid');
      if (validation) {
        validation.className = 'input-validation valid';
        validation.innerHTML = `✓ ${this.t.validFormat}`;
      }
    } else {
      card?.classList.add('invalid');
      if (validation) {
        validation.className = 'input-validation invalid';
        validation.innerHTML = `✗ ${this.t.invalidFormat}`;
      }
    }
    
    return result.valid;
  },
  
  getInputValues() {
    return {
      sni: Calculator.parseNum(document.getElementById('inputSni')?.value),
      inf: Calculator.parseNum(document.getElementById('inputInf')?.value),
      cav: Calculator.parseNum(document.getElementById('inputCav')?.value)
    };
  },
  
  setInputValues(sni, inf, cav) {
    const sniInput = document.getElementById('inputSni');
    const infInput = document.getElementById('inputInf');
    const cavInput = document.getElementById('inputCav');
    
    if (sniInput) {
      sniInput.value = sni || '';
      this.validateInput(sniInput);
    }
    if (infInput) {
      infInput.value = inf || '';
      this.validateInput(infInput);
    }
    if (cavInput) {
      cavInput.value = cav || '';
      this.validateInput(cavInput);
    }
  },
  
  // ==========================================
  // LANGUAGE
  // ==========================================
  setLanguage(lang) {
    if (!Translations[lang]) return;
    
    this.lang = lang;
    this.t = Translations[lang];
    Storage.set('F11_LANG', lang);
    
    // Update direction
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
    document.documentElement.lang = lang;
    
    this.updateLanguage();
    this.renderCamps();
    this.renderHistory();
    
    // Re-render chart if exists
    if (this.lastResult) {
      this.showChart(this.lastResult);
    }
  },
  
  updateLanguage() {
    const t = this.t;
    
    // Update active language button
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.lang === this.lang);
    });
    
    // Hero
    this.setText('logoText', t.title);
    this.setText('tagline', t.tagline);
    this.setHtml('hint', `${t.hintPrefix} <span class="hint-pill">360k</span> <span class="hint-pill">1.1m</span>`);
    
    // Onboarding
    this.setText('onboardingTitle', t.onboardingTitle);
    this.setText('onboardingText', t.onboardingText);
    this.setText('onboardingDismiss', t.onboardingDismiss);
    
    // Ticker
    this.setText('tickerBadge', t.tickerBadge);
    document.querySelectorAll('.ticker-text').forEach(el => {
      el.textContent = t.tickerMsg;
    });
    
    // Upload
    this.setText('uploadLabel', t.uploadLabel);
    this.setText('uploadGalleryLabel', t.uploadGallery);
    this.setText('uploadGallerySub', t.uploadGallerySub);
    this.setText('uploadCtaPill', t.uploadSelect);
    this.setText('uploadReplaceBtn', t.uploadReplace);
    this.setText('uploadRemoveBtn', t.uploadRemove);
    this.setUploadStatus(this._uploadStatus || 'empty');
    
    // Inputs
    this.setText('labelSni', t.sni);
    this.setText('labelInf', t.inf);
    this.setText('labelCav', t.cav);
    
    document.querySelectorAll('.input-field').forEach(input => {
      input.placeholder = t.placeholder;
    });
    
    document.querySelectorAll('.input-clear-btn').forEach(btn => {
      btn.textContent = `✕ ${t.clear}`;
    });
    
    // Camps
    this.setText('campsTitle', t.campsTitle);
    this.setText('campsSubtitle', t.campsSub);
    document.getElementById('campNameInput')?.setAttribute('placeholder', t.campNamePh);
    this.setText('campSaveBtn', `💾 ${t.campSave}`);
    
    // Actions
    this.setText('btnCalc', `⚔️ ${t.btnCalc}`);
    this.setText('btnSmart', `🧠 ${t.btnSmart}`);
    this.setText('btnCopy', `📋 ${t.btnCopy}`);
    this.setText('btnShare', `🔗 ${t.btnShare}`);
    this.setText('btnReset', `♻️ ${t.btnReset}`);
    this.setText('btnDownloadLabel', t.btnDownload);
    document.getElementById('btnDownload')?.setAttribute('aria-label', t.btnDownload);
    
    // Output idle state
    if (!this.lastResult) {
      this.setHtml('outputIdle', `
        <div class="output-idle-icon">${t.outputIdleIcon}</div>
        <div>${t.outputIdle}</div>
      `);
    }
    
    // History
    this.setText('historyTitle', `📜 ${t.historyTitle}`);
    this.setText('historyClearBtn', t.historyClear);
    
    // Footer
    this.setHtml('footerText', `${t.footerText} <span class="footer-brand">F11</span>`);
    
    // Confirm dialog
    this.setText('confirmCancel', t.confirmCancel);
  },
  
  setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  },
  
  setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  },
  
  // ==========================================
  // THEME
  // ==========================================
  toggleTheme() {
    document.body.classList.toggle('dark');
    const isDark = document.body.classList.contains('dark');
    Storage.set('F11_DARK', isDark ? '1' : '0');
    this.updateThemeButton();
    
    // Re-render chart with new colors
    if (this.lastResult) {
      this.drawChart(this.lastResult);
    }
  },
  
  updateThemeButton() {
    const isDark = document.body.classList.contains('dark');
    const btn = document.getElementById('themeToggle');
    if (btn) {
      btn.textContent = isDark ? `☀️ ${this.t.light}` : `🌙 ${this.t.dark}`;
    }
  },
  
  // ==========================================
  // ONBOARDING
  // ==========================================
  dismissOnboarding() {
    document.getElementById('onboarding')?.classList.add('hidden');
    Storage.set('F11_ONBOARDING_SEEN', '1');
  },
  
  // ==========================================
  // TICKER
  // ==========================================
  dismissTicker() {
    document.getElementById('ticker')?.classList.add('hidden');
    Storage.set('F11_TICKER_DISMISSED', '1');
  },
  
  // ==========================================
  // UPLOAD STATUS
  // ==========================================
  _uploadStatus: 'empty',

  setUploadStatus(state) {
    const preview = document.getElementById('uploadPreview');
    const statusEl = document.getElementById('uploadStatus');

    this._uploadStatus = state || 'empty';

    preview?.classList.remove('reading', 'success', 'error');

    let text = '—';
    if (this._uploadStatus === 'ready') {
      text = this.t.uploadStatusReady;
    } else if (this._uploadStatus === 'reading') {
      text = this.t.uploadStatusReading;
      preview?.classList.add('reading');
    } else if (this._uploadStatus === 'done') {
      text = this.t.uploadStatusDone;
      preview?.classList.add('success');
    } else if (this._uploadStatus === 'error') {
      text = this.t.uploadStatusError;
      preview?.classList.add('error');
    }

    if (statusEl) statusEl.textContent = text;
  },
  
  // ==========================================
  // IMAGE UPLOAD
  // ==========================================
  async handleImageUpload(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    
    // Show preview
    this.showUploadPreview(file);
    this.setUploadStatus('ready');
    
    // Show loading
    this.setLoadingText(this.t.loadingText);
    this.showLoading(true);
    this.setUploadStatus('reading');
    
    try {
      // Lazy load Tesseract
      if (!this.tesseractLoaded && typeof Tesseract === 'undefined') {
        await this.loadTesseract();
      }
      
      const result = await this.runOCR(file);
      
      if (result) {
        this.setInputValues(result.sni, result.inf, result.cav);
        this.toast(`✅ ${result.sni || 0} · ${result.inf || 0} · ${result.cav || 0}`);
        this.setUploadStatus('done');
        
        // Auto-analyze
        setTimeout(() => this.smartAnalyze(), 300);
      } else {
        this.toast(`⚠️ ${this.t.ocrFail}`);
        this.setUploadStatus('error');
      }
      
    } catch (e) {
      console.error('Image processing failed:', e);
      this.toast(`❌ ${this.t.toastError}`);
      this.setUploadStatus('error');
    } finally {
      this.showLoading(false);
      
      // Clear file input
      event.target.value = '';
    }
  },
  
  async loadTesseract() {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://unpkg.com/tesseract.js@5/dist/tesseract.min.js';
      script.onload = () => {
        this.tesseractLoaded = true;
        resolve();
      };
      script.onerror = reject;
      document.head.appendChild(script);
    });
  },
  
  async runOCR(file) {
    // OCR pipeline:
    // 1) Prefer cropped OCR over the troop totals row (avoids coordinates/unrelated text)
    // 2) Use per-column crops and robust token picking (not "first regex match")
    // 3) Fall back to full-image OCR with stricter parsing if crops fail

    this._lastOcrDebug = {
      mode: 'crops',
      crops: [],
      chosen: null,
      fallback: null
    };

    let worker;
    try {
      worker = await Tesseract.createWorker('eng');
      await worker.setParameters({
        tessedit_char_whitelist: '0123456789.kKmM ,',
        // Single uniform block of text
        tessedit_pageseg_mode: '6',
        // Improve accuracy
        tessedit_ocr_engine_mode: '1',
        preserve_interword_spaces: '1'
      });

      const bmp = await this._loadImageBitmap(file);
      const w = bmp.width || 0;
      const h = bmp.height || 0;

      // Candidate bands where the three troop totals usually live.
      // These are relative to the full screenshot size.
      const bands = [
        { y0: 0.20, y1: 0.32 },
        { y0: 0.24, y1: 0.36 },
        { y0: 0.28, y1: 0.40 },
        { y0: 0.32, y1: 0.44 },
        { y0: 0.34, y1: 0.46 },
        { y0: 0.36, y1: 0.48 },
        { y0: 0.38, y1: 0.50 },
        { y0: 0.40, y1: 0.52 },
        { y0: 0.42, y1: 0.54 },
        { y0: 0.44, y1: 0.56 },
        { y0: 0.46, y1: 0.58 },
        { y0: 0.48, y1: 0.60 },
        { y0: 0.50, y1: 0.62 },
        { y0: 0.52, y1: 0.64 },
        { y0: 0.54, y1: 0.66 },
        { y0: 0.56, y1: 0.68 },
        { y0: 0.58, y1: 0.70 },
        { y0: 0.60, y1: 0.72 },
        { y0: 0.62, y1: 0.74 },
        { y0: 0.65, y1: 0.77 }
      ];

      // Three columns (left / middle / right). Mapping for scout screenshots:
      // left = Fighters, middle = Snipers, right = Cavalry.
      const cols = [
        { name: 'left',  x0: 0.03, x1: 0.37 },
        { name: 'mid',   x0: 0.32, x1: 0.68 },
        { name: 'right', x0: 0.63, x1: 0.97 }
      ];

      let best = null;

      for (let bi = 0; bi < bands.length; bi++) {
        const band = bands[bi];
        const bandDebug = {
          bandIndex: bi,
          band,
          cols: []
        };

        let bandScore = 0;
        let hitCount = 0;
        const picked = { left: '', mid: '', right: '' };

        for (const col of cols) {
          const sx = Math.max(0, Math.floor(col.x0 * w));
          const ex = Math.min(w, Math.ceil(col.x1 * w));
          const sy = Math.max(0, Math.floor(band.y0 * h));
          const ey = Math.min(h, Math.ceil(band.y1 * h));
          const sw = Math.max(1, ex - sx);
          const sh = Math.max(1, ey - sy);

          const canvas = this._makeOcrCropCanvas(bmp, sx, sy, sw, sh, 2);
          const { data } = await worker.recognize(canvas);
          const bestTok = this._pickBestKmvToken(data);

          picked[col.name] = bestTok?.value || '';

          bandDebug.cols.push({
            name: col.name,
            rect: { sx, sy, sw, sh },
            text: String(data?.text || '').slice(0, 1200),
            picked: bestTok
          });

          if (bestTok?.value) {
            hitCount++;
            bandScore += (bestTok.score || 0);
          }
        }

        // Prefer bands that produce 3 clean tokens.
        bandScore += hitCount * 1000;

        // Penalize cases where the middle value looks like a TOTAL (approximately left+right).
        // This happens on some report layouts where the total troop count sits just above the 3 icons row.
        const absLeft = this._absFromKmv(picked.left);
        const absMid = this._absFromKmv(picked.mid);
        const absRight = this._absFromKmv(picked.right);
        if (absLeft > 0 && absRight > 0 && absMid > 0 && absMid > absLeft && absMid > absRight) {
          const sumLR = absLeft + absRight;
          if (sumLR > 0) {
            const relDiff = Math.abs(absMid - sumLR) / sumLR;
            if (relDiff < 0.25) {
              bandScore -= 900;
            }
          }
        }

        // Plausibility bonus: typical totals are >= 10k and <= 50m.
        const absVals = ['left', 'mid', 'right']
          .map((k) => this._absFromKmv(picked[k]))
          .filter((n) => typeof n === 'number' && isFinite(n) && n > 0);
        if (absVals.length >= 2) {
          const ok = absVals.filter((n) => n >= 5000 && n <= 100000000).length;
          bandScore += ok * 200;
        }

        bandDebug.picked = picked;
        bandDebug.bandScore = bandScore;
        this._lastOcrDebug.crops.push(bandDebug);

        if (!best || bandScore > best.bandScore) {
          best = { bandScore, picked, bandIndex: bi, band };
        }
      }

      if (best && (best.picked.left || best.picked.mid || best.picked.right)) {
        // Map: left=fighters, mid=snipers, right=cavalry
        const result = {
          sni: best.picked.mid || '',
          inf: best.picked.left || '',
          cav: best.picked.right || ''
        };

        // Require at least 2 values to accept crop-based OCR.
        const nonEmpty = [result.sni, result.inf, result.cav].filter(Boolean).length;
        if (nonEmpty >= 2) {
          this._lastOcrDebug.chosen = { ...best, result };
          return result;
        }
      }

      // Fallback: full image OCR, but pick values using word bboxes (row clustering).
      await worker.setParameters({ tessedit_pageseg_mode: '11' });
      const { data } = await worker.recognize(file);
      const picked = this._pickTotalsFromFullOcr(data, w, h);

      this._lastOcrDebug.fallback = {
        text: String(data?.text || '').slice(0, 3000),
        picked
      };

      if (picked && [picked.sni, picked.inf, picked.cav].filter((x) => x !== '').length >= 2) {
        return picked;
      }

      return null;
    } catch (e) {
      console.error('OCR failed:', e);
      return null;
    } finally {
      try {
        if (worker) await worker.terminate();
      } catch (_) {
        // ignore
      }
    }
  },

  async _loadImageBitmap(file) {
    // Prefer createImageBitmap; fall back to HTMLImageElement.
    try {
      // eslint-disable-next-line no-undef
      return await createImageBitmap(file);
    } catch (_) {
      const url = URL.createObjectURL(file);
      try {
        const img = await new Promise((resolve, reject) => {
          const el = new Image();
          el.onload = () => resolve(el);
          el.onerror = reject;
          el.src = url;
        });
        return img;
      } finally {
        try { URL.revokeObjectURL(url); } catch (_) {}
      }
    }
  },

  _makeOcrCropCanvas(source, sx, sy, sw, sh, scale = 3) {
    const cw = Math.max(1, Math.round(sw * scale));
    const ch = Math.max(1, Math.round(sh * scale));
    const canvas = document.createElement('canvas');
    canvas.width = cw;
    canvas.height = ch;

    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(source, sx, sy, sw, sh, 0, 0, cw, ch);

    // Simple preprocessing: grayscale + contrast boost.
    try {
      const imgData = ctx.getImageData(0, 0, cw, ch);
      const d = imgData.data;
      const contrast = 1.8; // Increased for better OCR on game screenshots
      for (let i = 0; i < d.length; i += 4) {
        const r = d[i];
        const g = d[i + 1];
        const b = d[i + 2];
        let y = 0.2126 * r + 0.7152 * g + 0.0722 * b;
        y = (y - 128) * contrast + 128;
        y = Math.max(0, Math.min(255, y));
        d[i] = d[i + 1] = d[i + 2] = y;
        // keep alpha
      }
      ctx.putImageData(imgData, 0, 0);
    } catch (_) {
      // Some browsers may block getImageData for certain sources; keep unprocessed.
    }

    return canvas;
  },

  _pickBestKmvToken(data) {
    const words = Array.isArray(data?.words) ? data.words : [];
    const candidates = [];

    const norm = (s) => String(s || '')
      .trim()
      .toLowerCase()
      .replace(/,/g, '.')
      .replace(/\s+/g, '');

    const isSuffix = (s) => s === 'k' || s === 'm';
    const isZero = (s) => s === '0' || s === '0.' || s === '0.0' || s === '0.00';
    const isValid = (s) => /^\d+(?:\.\d+)?[km]$/.test(s) || isZero(s);

    for (let i = 0; i < words.length; i++) {
      const a = norm(words[i]?.text);
      const ca = Number(words[i]?.confidence || 0);
      if (a) {
        candidates.push({ raw: a, conf: ca });
      }
      const b = norm(words[i + 1]?.text);
      const cb = Number(words[i + 1]?.confidence || 0);
      if (a && b && isSuffix(b)) {
        candidates.push({ raw: a + b, conf: (ca + cb) / 2 });
      }
    }

    // Also try from text (in case words misses).
    const text = norm(data?.text);
    if (text) {
      const joined = text.replace(/(\d+(?:\.\d+)?)\s*([km])/g, '$1$2');
      const re = /\b\d+(?:\.\d+)?[km]\b/g;
      let m;
      while ((m = re.exec(joined))) {
        candidates.push({ raw: m[0], conf: 50 });
      }
    }

    let best = null;
    for (const c of candidates) {
      const raw = String(c.raw || '');
      if (!isValid(raw)) continue;
      const formatted = this._formatKmv(raw);
      if (formatted === '') continue;
      const abs = this._absFromKmv(formatted);
      if (!(abs >= 0) || abs > 50000000) continue;

      let score = (Number(c.conf) || 0);
      if (abs === 0) score -= 10;
      if (abs >= 10000 && abs <= 30000000) score += 25;
      if (abs >= 100000) score += 10;

      // Prefer tokens that include a suffix already (always true here) and are not tiny.
      if (abs > 0 && abs < 5000) score -= 30;

      if (!best || score > best.score) {
        best = { value: formatted, raw, conf: Number(c.conf) || 0, abs, score };
      }
    }

    return best;
  },

  _pickTopKmvTokensFromText(text, limit = 3) {
    const t = String(text || '')
      .toLowerCase()
      .replace(/,/g, '.')
      .replace(/\s+/g, ' ');

    // Join cases like "360.0\n k".
    const joined = t.replace(/(\d+(?:\.\d+)?)\s*([km])\b/g, '$1$2');
    const re = /\b(\d+(?:\.\d+)?)([km])\b/g;
    const found = [];

    let m;
    while ((m = re.exec(joined))) {
      const raw = `${m[1]}${m[2]}`;
      const v = this._formatKmv(raw);
      const abs = this._absFromKmv(v);
      if (abs > 0 && abs <= 50000000) {
        found.push({ v, abs });
      }
    }

    // Filter out obvious coordinate-like noise: tiny k values.
    const filtered = found
      .filter((x) => x.abs >= 10000)
      .sort((a, b) => b.abs - a.abs);

    const out = [];
    for (const item of filtered) {
      out.push(item.v);
      if (out.length >= limit) break;
    }

    return out;
  },

  _absFromKmv(token) {
    const s = String(token || '').toLowerCase().trim();
    if (s === '0') return 0;
    const m = s.match(/^(\d+(?:\.\d+)?)([km])$/);
    if (!m) return NaN;
    const n = parseFloat(m[1]);
    if (!isFinite(n)) return NaN;
    return m[2] === 'm' ? n * 1000000 : n * 1000;
  },

  _formatKmv(token) {
    // Normalize formats like 360.0k / 1.10m -> 360k / 1.1m
    const s = String(token || '')
      .trim()
      .toLowerCase()
      .replace(/,/g, '.');
    if (s === '0' || s === '0.' || s === '0.0' || s === '0.00') return '0';
    const m = s.match(/^(\d+(?:\.\d+)?)([km])$/);
    if (!m) return '';
    const n = parseFloat(m[1]);
    if (!isFinite(n) || n <= 0) return '';
    const suf = m[2];

    // Keep up to 1 decimal, strip trailing .0
    const fixed = n.toFixed(1);
    const cleaned = fixed.endsWith('.0') ? fixed.slice(0, -2) : fixed;
    return cleaned + suf;
  },

  _pickTotalsFromFullOcr(data, w, h) {
    const words = Array.isArray(data?.words) ? data.words : [];
    const norm = (s) => String(s || '')
      .trim()
      .toLowerCase()
      .replace(/,/g, '.')
      .replace(/\s+/g, '');

    const isSuffix = (s) => s === 'k' || s === 'm';
    const isZero = (s) => s === '0' || s === '0.' || s === '0.0' || s === '0.00';
    const isKmv = (s) => /^\d+(?:\.\d+)?[km]$/.test(s);

    const candidates = [];
    const push = (raw, conf, bbox) => {
      const formatted = this._formatKmv(raw);
      if (formatted === '') return;
      const abs = this._absFromKmv(formatted);
      if (!(abs >= 0) || abs > 50000000) return;
      if (abs > 0 && abs < 10000) return; // drop tiny noise

      const b = bbox || {};
      const x0 = Number(b.x0 ?? b.left ?? 0);
      const y0 = Number(b.y0 ?? b.top ?? 0);
      const x1 = Number(b.x1 ?? b.right ?? 0);
      const y1 = Number(b.y1 ?? b.bottom ?? 0);
      const xc = (x0 + x1) / 2;
      const yc = (y0 + y1) / 2;
      const hh = Math.max(0, y1 - y0);

      let score = (Number(conf) || 0);
      if (abs === 0) score -= 10;
      if (abs >= 10000 && abs <= 30000000) score += 25;
      if (abs >= 100000) score += 10;
      if (hh > 0) score += Math.min(20, hh / 3);

      candidates.push({ value: formatted, abs, conf: Number(conf) || 0, score, xc, yc, hh });
    };

    for (let i = 0; i < words.length; i++) {
      const a = norm(words[i]?.text);
      const ca = Number(words[i]?.confidence || 0);
      const bboxA = words[i]?.bbox;
      if (a && (isKmv(a) || isZero(a))) {
        push(a, ca, bboxA);
      }
      const b = norm(words[i + 1]?.text);
      const cb = Number(words[i + 1]?.confidence || 0);
      const bboxB = words[i + 1]?.bbox;
      if (a && b && isSuffix(b) && /^\d+(?:\.\d+)?$/.test(a)) {
        push(a + b, (ca + cb) / 2, bboxA || bboxB);
      }
    }

    if (!candidates.length || !w || !h) return null;

    // Cluster by y-center into rows.
    const sorted = candidates.slice().sort((p, q) => p.yc - q.yc);
    const tol = Math.max(14, h * 0.02);
    const rows = [];
    let cur = [];
    let lastY = null;
    for (const c of sorted) {
      if (lastY === null || Math.abs(c.yc - lastY) <= tol) {
        cur.push(c);
      } else {
        rows.push(cur);
        cur = [c];
      }
      lastY = c.yc;
    }
    if (cur.length) rows.push(cur);

    const colOf = (xc) => {
      const r = xc / w;
      if (r < 0.42) return 'left';
      if (r > 0.58) return 'right';
      return 'mid';
    };

    let bestRow = null;
    for (const row of rows) {
      // Keep only best token per column in this row.
      const byCol = { left: null, mid: null, right: null };
      for (const c of row) {
        const col = colOf(c.xc);
        if (!byCol[col] || c.score > byCol[col].score) byCol[col] = c;
      }

      const occupied = Object.values(byCol).filter(Boolean).length;
      if (occupied < 2) continue;

      // Prefer rows in the middle of the screenshot.
      const yAvg = row.reduce((s, c) => s + c.yc, 0) / row.length;
      const yRel = yAvg / h;

      let rowScore = 0;
      for (const c of Object.values(byCol)) rowScore += c ? c.score : 0;
      rowScore += occupied * 1000;
      if (yRel >= 0.25 && yRel <= 0.80) rowScore += 150;
      if (yRel >= 0.35 && yRel <= 0.70) rowScore += 150;

      // Penalize rows that look like "total" (single big number) + two empties.
      if (occupied === 2) rowScore -= 50;

      const rowObj = { byCol, rowScore, yRel };
      if (!bestRow || rowScore > bestRow.rowScore) bestRow = rowObj;
    }

    if (!bestRow) return null;

    // Map left=fighters, mid=snipers, right=cavalry.
    return {
      sni: bestRow.byCol.mid ? bestRow.byCol.mid.value : '',
      inf: bestRow.byCol.left ? bestRow.byCol.left.value : '',
      cav: bestRow.byCol.right ? bestRow.byCol.right.value : ''
    };
  },
  
  showUploadPreview(file) {
    const preview = document.getElementById('uploadPreview');
    const thumb = document.getElementById('uploadThumb');
    const name = document.getElementById('uploadFileName');
    const size = document.getElementById('uploadFileSize');
    
    if (!preview) return;
    
    // Revoke any previous preview URL to avoid leaks.
    try {
      if (this._previewObjectUrl) URL.revokeObjectURL(this._previewObjectUrl);
    } catch (_) {}

    const url = URL.createObjectURL(file);
    this._previewObjectUrl = url;
    if (thumb) thumb.src = url;
    if (name) name.textContent = file.name.length > 25 ? file.name.substring(0, 22) + '...' : file.name;
    if (size) {
      const kb = (file.size / 1024).toFixed(0);
      size.textContent = kb > 1024 ? (kb / 1024).toFixed(1) + ' MB' : kb + ' KB';
    }
    
    preview.classList.add('show');
    document.getElementById('btnDownload')?.removeAttribute('disabled');

    // Switch scout card to image state
    const scoutCard = document.getElementById('scoutCard');
    const scoutImg  = document.getElementById('scoutImg');
    if (scoutCard && scoutImg) {
      scoutImg.src = url;
      scoutCard.classList.add('has-image');
    }
  },

  clearUploadPreview() {
    const preview = document.getElementById('uploadPreview');
    const thumb = document.getElementById('uploadThumb');
    const name = document.getElementById('uploadFileName');
    const size = document.getElementById('uploadFileSize');
    const input = document.getElementById('uploadInput');

    preview?.classList.remove('show', 'reading', 'success', 'error');
    if (thumb) thumb.setAttribute('src', '');
    if (name) name.textContent = '—';
    if (size) size.textContent = '—';
    if (input) input.value = '';

    try {
      if (this._previewObjectUrl) URL.revokeObjectURL(this._previewObjectUrl);
    } catch (_) {}
    this._previewObjectUrl = '';

    this.setUploadStatus('empty');
    document.getElementById('btnDownload')?.setAttribute('disabled', '');

    // Reset scout card to video state
    const scoutCard = document.getElementById('scoutCard');
    const scoutImg  = document.getElementById('scoutImg');
    if (scoutCard && scoutImg) {
      scoutImg.src = '';
      scoutCard.classList.remove('has-image');
    }
  },
  
  // ==========================================
  // CAMPS
  // ==========================================
  saveCurrentCamp() {
    const nameInput = document.getElementById('campNameInput');
    const name = (nameInput?.value || '').trim();
    
    if (!name) {
      this.toast(`⚠️ ${this.t.campNoName}`);
      nameInput?.focus();
      return;
    }
    
    const values = this.getInputValues();
    if (values.sni + values.inf + values.cav === 0) {
      this.toast(`⚠️ ${this.t.campNoTroops}`);
      return;
    }
    
    const camp = {
      name,
      sni: document.getElementById('inputSni')?.value || '',
      inf: document.getElementById('inputInf')?.value || '',
      cav: document.getElementById('inputCav')?.value || ''
    };
    
    const result = Camps.save(camp);
    
    if (nameInput) nameInput.value = '';
    this.renderCamps();
    
    this.toast(`✅ ${result === 'updated' ? this.t.campUpdated : this.t.campSaved}`);
  },
  
  loadCamp(index) {
    const camp = Camps.get(index);
    if (!camp) return;
    
    this.setInputValues(camp.sni, camp.inf, camp.cav);
    this.toast(`⚡ ${camp.name}`);
    
    // Auto-analyze
    setTimeout(() => this.smartAnalyze(), 300);
  },
  
  deleteCamp(index) {
    const camp = Camps.get(index);
    if (!camp) return;
    
    this.showConfirm(
      this.t.confirmDeleteCampTitle,
      `"${camp.name}" - ${this.t.confirmDeleteCampMsg}`,
      () => {
        Camps.delete(index);
        this.renderCamps();
        this.toast(`🗑️ ${camp.name}`);
      }
    );
  },
  
  renderCamps() {
    const camps = Camps.getAll();
    const countEl = document.getElementById('campsCount');
    const listEl = document.getElementById('campsList');
    
    if (countEl) countEl.textContent = camps.length;
    
    if (!listEl) return;
    
    if (camps.length === 0) {
      listEl.innerHTML = `<div class="camps-empty">📭 ${this.t.campsEmpty}</div>`;
      return;
    }
    
    listEl.innerHTML = camps.map((camp, idx) => `
      <div class="camp-card">
        <div class="camp-card-info">
          <div class="camp-card-name">🏕️ ${this.escapeHtml(camp.name)}</div>
          <div class="camp-card-troops">${this.t.sni}: ${this.escapeHtml(camp.sni || '—')} · ${this.t.inf}: ${this.escapeHtml(camp.inf || '—')} · ${this.t.cav}: ${this.escapeHtml(camp.cav || '—')}</div>
        </div>
        <button class="camp-load-btn" onclick="DalyApp.loadCamp(${idx})">⚡ ${this.t.campLoad}</button>
        <button class="camp-del-btn" onclick="DalyApp.deleteCamp(${idx})" title="${this.t.confirmDeleteCampTitle}">🗑️</button>
      </div>
    `).join('');
  },
  
  escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  },
  
  // ==========================================
  // CALCULATION
  // ==========================================
  calculate() {
    const enemy = this.getInputValues();
    const result = Calculator.calculate(enemy);
    
    if (!result) {
      this.toast(this.t.toastNeed);
      return;
    }
    
    this.lastResult = result;
    this.showResult(result);
    this.showChart(result);
    
    // Add to history
    History.add({
      enemy,
      primary: result.primary,
      secondary: result.secondary,
      primaryPct: result.primaryPct,
      secondaryPct: result.secondaryPct
    });
    this.renderHistory();
    
    // Set copy text
    this.lastCopyText = `${this.typeText(result.primary)} ${result.primaryPct}% + ${this.typeText(result.secondary)} ${result.secondaryPct}%`;
  },
  
  smartAnalyze() {
    const enemy = this.getInputValues();
    const result = Calculator.smartAnalysis(enemy);
    
    if (!result) {
      this.toast(this.t.toastNeed);
      return;
    }
    
    this.lastResult = result;
    this.showSmartResult(result);
    this.showChart(result);
    
    // Add to history
    History.add({
      enemy,
      primary: result.primary,
      secondary: result.secondary,
      primaryPct: result.primaryPct,
      secondaryPct: result.secondaryPct
    });
    this.renderHistory();
    
    // Set copy text
    this.lastCopyText = `${this.typeText(result.primary)} ${result.primaryPct}% + ${this.typeText(result.secondary)} ${result.secondaryPct}%`;
  },
  
  showResult(result) {
    const t = this.t;
    const output = document.getElementById('output');
    const outputIdle = document.getElementById('outputIdle');
    const resultSection = document.getElementById('resultSection');
    const smartBox = document.getElementById('smartBox');
    
    if (outputIdle) outputIdle.style.display = 'none';
    if (smartBox) smartBox.classList.remove('show');
    if (resultSection) resultSection.classList.add('show');
    
    // Enemy stats
    this.setHtml('enemyStats', `
      <div class="enemy-stat">
        <img src="images/sniper.png" alt="" class="enemy-stat-icon">
        <div class="enemy-stat-value">${Calculator.formatNum(result.enemy.sni)}</div>
        <div class="enemy-stat-label">${t.sni}</div>
      </div>
      <div class="enemy-stat">
        <img src="images/fighter.png" alt="" class="enemy-stat-icon">
        <div class="enemy-stat-value">${Calculator.formatNum(result.enemy.inf)}</div>
        <div class="enemy-stat-label">${t.inf}</div>
      </div>
      <div class="enemy-stat">
        <img src="images/cavalry.png" alt="" class="enemy-stat-icon">
        <div class="enemy-stat-value">${Calculator.formatNum(result.enemy.cav)}</div>
        <div class="enemy-stat-label">${t.cav}</div>
      </div>
    `);
    
    // Recommendation
    this.setHtml('recTroops', `
      <div class="rec-troop">
        <img src="${this.typeIcon(result.primary)}" alt="" class="rec-troop-icon">
        <div class="rec-troop-info">
          <div class="rec-troop-name">${this.typeText(result.primary)}</div>
          <div class="rec-troop-pct">${result.primaryPct}%</div>
        </div>
      </div>
      <div class="rec-troop">
        <img src="${this.typeIcon(result.secondary)}" alt="" class="rec-troop-icon">
        <div class="rec-troop-info">
          <div class="rec-troop-name">${this.typeText(result.secondary)}</div>
          <div class="rec-troop-pct">${result.secondaryPct}%</div>
        </div>
      </div>
    `);
    
    // Reason
    this.setHtml('resultReason', `
      <strong>${t.reason1}</strong> ${t.reason2} <strong>${this.typeText(result.major)}</strong>, 
      ${t.reason3} <strong>${this.typeText(result.primary)}</strong>. 
      ${t.reason4} <strong>${this.typeText(result.secondary)}</strong> ${t.reason5} <strong>${this.typeText(result.primary)}</strong>.
    `);
    
    // Flash animation
    if (output) {
      output.classList.remove('flash');
      requestAnimationFrame(() => output.classList.add('flash'));
    }
  },
  
  showSmartResult(result) {
    const t = this.t;
    const outputIdle = document.getElementById('outputIdle');
    const resultSection = document.getElementById('resultSection');
    const smartBox = document.getElementById('smartBox');
    
    if (outputIdle) outputIdle.style.display = 'none';
    if (resultSection) resultSection.classList.remove('show');
    if (smartBox) smartBox.classList.add('show');
    
    // Build why lines
    const whyLines = [];
    whyLines.push(`<li><strong>${this.typeText(result.primary)}</strong> ${t.smartWhy1} <strong>${this.typeText(result.dominant)}</strong>.</li>`);
    
    if (result.vulnerabilityPct > 18) {
      whyLines.push(`<li>${t.smartWhy2} <strong>${this.typeText(result.vulnerability)}</strong> (${result.vulnerabilityPct}%). ${t.smartWhy3} <strong>${this.typeText(result.secondary)}</strong>.</li>`);
    } else {
      whyLines.push(`<li>${t.smartWhy4}.</li>`);
    }
    
    whyLines.push(`<li>${t.smartWhy5} <strong style="color:var(--primary)">${result.primaryPct}/${result.secondaryPct}</strong>.</li>`);
    
    this.setHtml('smartBox', `
      <div class="smart-title">🧠 ${t.smartTitle}</div>
      <div class="smart-subtitle">${t.smartSub}</div>
      
      <div class="smart-grid">
        <div class="smart-pill">
          📊 ${t.smartEnemy}: ${t.sni} ${result.distribution.sni}% · ${t.inf} ${result.distribution.inf}% · ${t.cav} ${result.distribution.cav}%
        </div>
        <div class="smart-pill">
          ✅ ${t.smartRec}: <strong style="margin: 0 5px;">${this.typeText(result.primary)} ${result.primaryPct}%</strong> + <strong>${this.typeText(result.secondary)} ${result.secondaryPct}%</strong>
        </div>
      </div>
      
      <div class="smart-why">
        <div class="smart-why-title">${t.smartWhy}</div>
        <ul>${whyLines.join('')}</ul>
        <div class="smart-note">💡 ${t.smartNote}</div>
      </div>
    `);
  },
  
  typeText(type) {
    const t = this.t;
    if (type === 'sni') return t.sni;
    if (type === 'inf') return t.inf;
    return t.cav;
  },
  
  typeIcon(type) {
    if (type === 'sni') return 'images/sniper.png';
    if (type === 'inf') return 'images/fighter.png';
    return 'images/cavalry.png';
  },
  
  typeColor(type) {
    if (type === 'sni') return 'var(--sniper-color)';
    if (type === 'inf') return 'var(--fighter-color)';
    return 'var(--cavalry-color)';
  },
  
  // ==========================================
  // CHART
  // ==========================================
  showChart(result) {
    const chartSection = document.getElementById('chartSection');
    if (!chartSection) return;
    
    chartSection.classList.add('show');
    
    // Update ratio text
    this.setText('chartRatio', `${result.primaryPct} / ${result.secondaryPct}`);
    this.setText('chartRatioLabel', this.t.ratioHint);
    this.setText('chartLegendTitle', this.t.legendTitle);
    
    // Update legend
    const legendA = document.getElementById('legendA');
    const legendB = document.getElementById('legendB');
    
    if (legendA) {
      legendA.querySelector('.legend-dot').style.background = this.typeColor(result.primary);
      legendA.querySelector('.legend-icon').src = this.typeIcon(result.primary);
      legendA.querySelector('.legend-name').textContent = this.typeText(result.primary);
      legendA.querySelector('.legend-pct').textContent = `${result.primaryPct}%`;
    }
    
    if (legendB) {
      legendB.querySelector('.legend-dot').style.background = this.typeColor(result.secondary);
      legendB.querySelector('.legend-icon').src = this.typeIcon(result.secondary);
      legendB.querySelector('.legend-name').textContent = this.typeText(result.secondary);
      legendB.querySelector('.legend-pct').textContent = `${result.secondaryPct}%`;
    }
    
    // Draw donut chart
    this.drawChart(result);
  },
  
  hideChart() {
    document.getElementById('chartSection')?.classList.remove('show');
  },
  
  drawChart(result) {
    const canvas = document.getElementById('chartCanvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;
    const cx = W / 2;
    const cy = H / 2;
    const r = Math.min(W, H) / 2 - 20;
    const thickness = 22;
    
    const isDark = document.body.classList.contains('dark');
    
    // Colors
    const getColor = (type) => {
      if (type === 'sni') return isDark ? '#60a5fa' : '#3b82f6';
      if (type === 'inf') return isDark ? '#fbbf24' : '#f59e0b';
      return isDark ? '#a78bfa' : '#8b5cf6';
    };
    
    const colorA = getColor(result.primary);
    const colorB = getColor(result.secondary);
    
    // Animation
    const duration = 1000;
    const startTime = performance.now();
    
    const animate = (timestamp) => {
      let progress = (timestamp - startTime) / duration;
      if (progress > 1) progress = 1;
      
      const ease = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      
      ctx.clearRect(0, 0, W, H);
      
      // Background ring
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = isDark ? '#1e2530' : '#e2e8f0';
      ctx.lineWidth = thickness;
      ctx.stroke();
      
      const startAngle = -Math.PI / 2;
      const aShare = result.primaryPct / 100;
      const currentA = aShare * ease;
      const aEnd = startAngle + (Math.PI * 2 * currentA);
      
      ctx.lineCap = 'round';
      
      // Secondary arc
      if (result.secondaryPct > 0) {
        const bShare = (100 - result.primaryPct) / 100;
        const currentB = bShare * ease;
        const bEnd = aEnd + (Math.PI * 2 * currentB);
        
        ctx.beginPath();
        ctx.arc(cx, cy, r, aEnd, bEnd);
        ctx.strokeStyle = colorB;
        ctx.lineWidth = thickness;
        ctx.shadowColor = isDark ? 'rgba(0,0,0,0.5)' : 'rgba(0,0,0,0.2)';
        ctx.shadowBlur = 8;
        ctx.shadowOffsetX = 2;
        ctx.shadowOffsetY = 4;
        ctx.stroke();
      }
      
      // Primary arc (on top)
      ctx.beginPath();
      ctx.arc(cx, cy, r, startAngle, aEnd);
      ctx.strokeStyle = colorA;
      ctx.lineWidth = thickness;
      ctx.shadowColor = isDark ? 'rgba(0,0,0,0.6)' : 'rgba(0,0,0,0.3)';
      ctx.shadowBlur = 12;
      ctx.shadowOffsetX = 3;
      ctx.shadowOffsetY = 6;
      ctx.stroke();
      
      ctx.shadowColor = 'transparent';
      
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    
    requestAnimationFrame(animate);
  },
  
  // ==========================================
  // HISTORY
  // ==========================================
  renderHistory() {
    const history = History.getAll();
    const section = document.getElementById('historySection');
    const list = document.getElementById('historyList');
    
    if (!section || !list) return;
    
    if (history.length === 0) {
      section.style.display = 'none';
      return;
    }
    
    section.style.display = 'block';
    
    list.innerHTML = history.map((entry, idx) => `
      <div class="history-item" onclick="DalyApp.loadHistory(${idx})">
        <div class="history-item-time">${History.formatTime(entry.timestamp)}</div>
        <div class="history-item-result">${this.typeText(entry.primary)} ${entry.primaryPct}% + ${this.typeText(entry.secondary)} ${entry.secondaryPct}%</div>
        <div class="history-item-troops">${Calculator.formatNum(entry.enemy.sni + entry.enemy.inf + entry.enemy.cav)}</div>
      </div>
    `).join('');
  },
  
  loadHistory(index) {
    const history = History.getAll();
    const entry = history[index];
    
    if (!entry) return;
    
    this.setInputValues(
      Calculator.formatNum(entry.enemy.sni),
      Calculator.formatNum(entry.enemy.inf),
      Calculator.formatNum(entry.enemy.cav)
    );
    
    setTimeout(() => this.smartAnalyze(), 200);
  },
  
  // ==========================================
  // COPY / SHARE
  // ==========================================
  async copyResult() {
    const t = this.t;
    const text = this.lastCopyText;
    
    if (!text) {
      this.toast(t.toastNeed);
      return;
    }
    
    try {
      await navigator.clipboard.writeText(text);
      this.toast(`✅ ${t.copied}`);
      
      const btn = document.getElementById('btnCopy');
      if (btn) {
        const original = btn.textContent;
        btn.textContent = `✅ ${t.copied}`;
        setTimeout(() => btn.textContent = original, 1500);
      }
    } catch (e) {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      
      this.toast(`✅ ${t.copied}`);
    }
  },
  
  async shareResult() {
    const t = this.t;
    
    if (!this.lastCopyText) {
      this.toast(t.toastNeed);
      return;
    }
    
    const text = `${t.recommendation}: ${this.lastCopyText}`;
    const url = window.location.href;
    
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'Daly Alpha',
          text,
          url
        });
        this.toast(`✅ ${t.shared}`);
        return;
      } catch (e) {}
    }
    
    // Fallback to copy
    try {
      await navigator.clipboard.writeText(`${text}\n${url}`);
      this.toast(`✅ ${t.shared}`);
    } catch (e) {
      this.toast(`✅ ${t.copied}`);
    }
  },
  
  // ==========================================
  // DOWNLOAD UPLOADED IMAGE
  // ==========================================
  downloadUploadedImage() {
    const thumb = document.getElementById('uploadThumb');
    if (!thumb || !thumb.src || thumb.src === window.location.href) return;

    const a = document.createElement('a');
    a.href = thumb.src;
    a.download = 'scout-report.png';
    a.click();
  },

  // ==========================================
  // RESET
  // ==========================================
  confirmReset() {
    this.showConfirm(
      this.t.confirmResetTitle,
      this.t.confirmResetMsg,
      () => this.reset()
    );
  },
  
  reset() {
    // Clear inputs
    this.setInputValues('', '', '');
    
    // Clear results
    this.lastResult = null;
    this.lastCopyText = '';
    
    // Reset output
    const outputIdle = document.getElementById('outputIdle');
    const resultSection = document.getElementById('resultSection');
    const smartBox = document.getElementById('smartBox');
    
    if (outputIdle) {
      outputIdle.style.display = 'block';
      outputIdle.innerHTML = `
        <div class="output-idle-icon">${this.t.outputIdleIcon}</div>
        <div>${this.t.outputIdle}</div>
      `;
    }
    if (resultSection) resultSection.classList.remove('show');
    if (smartBox) smartBox.classList.remove('show');
    
    this.hideChart();
    this.clearUploadPreview();
    
    this.toast(this.t.toastReset);
  },
  
  // ==========================================
  // CONFIRM DIALOG
  // ==========================================
  showConfirm(title, message, callback) {
    const overlay = document.getElementById('confirmOverlay');
    const titleEl = document.getElementById('confirmTitle');
    const messageEl = document.getElementById('confirmMessage');
    const okBtn = document.getElementById('confirmOk');
    
    if (titleEl) titleEl.textContent = title;
    if (messageEl) messageEl.textContent = message;
    if (okBtn) okBtn.textContent = this.t.confirmOk;
    
    this.confirmCallback = callback;
    overlay?.classList.add('show');
  },
  
  closeConfirm() {
    document.getElementById('confirmOverlay')?.classList.remove('show');
    this.confirmCallback = null;
  },
  
  // ==========================================
  // LOADING
  // ==========================================
  showLoading(show) {
    const overlay = document.getElementById('loadingOverlay');
    overlay?.classList.toggle('active', show);
  },
  
  setLoadingText(text) {
    const el = document.getElementById('loadingText');
    if (el) el.textContent = text;
  },
  
  // ==========================================
  // TOAST
  // ==========================================
  toast(message) {
    const el = document.getElementById('toast');
    if (!el) return;
    
    el.textContent = message;
    el.classList.add('show');
    
    clearTimeout(this._toastTimer);
    this._toastTimer = setTimeout(() => {
      el.classList.remove('show');
    }, 2500);
  }
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  DalyApp.init();
});

// Make DalyApp available globally for inline handlers
window.DalyApp = DalyApp;