/**
 * Centro Analisi P.Q.A. S.r.l. — Logica Frontend Alpine.js
 * Registrata tramite Alpine.data() senza espressioni inline complesse nell'HTML.
 */
document.addEventListener('alpine:init', () => {
  const stateEl = document.getElementById('pqa-initial-state');
  let initialState = {};
  if (stateEl) {
    try {
      initialState = JSON.parse(stateEl.textContent || '{}');
    } catch (_) {
      initialState = {};
    }
  }

  Alpine.data('pqaSite', () => ({
    mobileMenuOpen: false,
    scrolled: false,
    activeSection: 'intro',
    expandedService: 'acque',
    mapUnlocked: false,
    mapEmbedUrl: initialState.mapEmbedUrl || '',
    docs: initialState.documents || {},

    // Modali (Privacy / Cookie / Anteprima PDF)
    legalModal: null, // 'privacy' | 'cookie' | null
    pdfModal: {
      open: false,
      title: '',
      revision: '',
      size: '',
      viewUrl: '',
      downloadUrl: '',
    },

    // Form Contatti AJAX
    form: {
      name: '',
      email: '',
      phone: '',
      subject: 'Qualità delle Acque & Ricerca Legionella',
      message: '',
      privacy_consent: false,
      company_website: '', // Honeypot invisibile
    },
    formLoading: false,
    formSuccess: '',
    formError: '',
    fieldErrors: {},

    init() {
      this.onScroll();
      window.addEventListener('scroll', () => this.onScroll(), { passive: true });
      window.addEventListener('resize', () => {
        if (window.innerWidth > 1040 && this.mobileMenuOpen) {
          this.mobileMenuOpen = false;
        }
      }, { passive: true });

      this.$watch('legalModal', () => this.syncBodyLock());
      this.$watch('pdfModal.open', () => this.syncBodyLock());
      this.$watch('mobileMenuOpen', () => this.syncBodyLock());
    },

    syncBodyLock() {
      const locked = Boolean(this.legalModal || this.pdfModal.open || this.mobileMenuOpen);
      document.body.classList.toggle('pqa-modal-open', locked);
    },

    onScroll() {
      this.scrolled = window.scrollY > 18;
      const sections = ['intro', 'azienda', 'organizzazione', 'contatti'];
      const offset = window.scrollY + 180;
      for (const id of sections) {
        const el = document.getElementById(id);
        if (el && offset >= el.offsetTop) {
          this.activeSection = id;
        }
      }
    },

    toggleService(serviceKey) {
      this.expandedService = this.expandedService === serviceKey ? '' : serviceKey;
    },

    requestServiceQuote(subjectLabel) {
      this.form.subject = subjectLabel;
      this.mobileMenuOpen = false;
      const contactEl = document.getElementById('contatti');
      if (contactEl) {
        contactEl.scrollIntoView({ behavior: 'smooth' });
      }
      setTimeout(() => {
        const nameInput = document.getElementById('contact-name');
        if (nameInput) {
          nameInput.focus({ preventScroll: true });
        }
      }, 450);
    },

    openPdfPreview(docOrKey) {
      const doc = typeof docOrKey === 'string' ? this.docs[docOrKey] : docOrKey;
      if (!doc || !doc.viewUrl) {
        return;
      }
      this.pdfModal = {
        open: true,
        title: doc.title || 'Documento Ufficiale',
        revision: doc.revision || '',
        size: doc.size || '',
        viewUrl: doc.viewUrl,
        downloadUrl: doc.downloadUrl || doc.viewUrl,
      };
    },

    closePdfPreview() {
      this.pdfModal.open = false;
      setTimeout(() => {
        if (!this.pdfModal.open) {
          this.pdfModal.viewUrl = '';
        }
      }, 200);
    },

    openLegal(type) {
      this.legalModal = type;
    },

    closeAllModals() {
      this.legalModal = null;
      if (this.pdfModal.open) {
        this.closePdfPreview();
      }
      this.mobileMenuOpen = false;
    },

    unlockMap() {
      this.mapUnlocked = true;
    },

    lockMap() {
      this.mapUnlocked = false;
    },

    async submitContact() {
      this.formError = '';
      this.formSuccess = '';
      this.fieldErrors = {};

      // Validazione rapida lato client
      if (this.form.name.trim().length < 2) {
        this.fieldErrors.name = 'Inserisci il tuo nome o la ragione sociale.';
      }
      const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRe.test(this.form.email.trim())) {
        this.fieldErrors.email = 'Inserisci un indirizzo email valido.';
      }
      if (this.form.message.trim().length < 10) {
        this.fieldErrors.message = 'Inserisci almeno 10 caratteri per descrivere la richiesta.';
      }
      if (!this.form.privacy_consent) {
        this.fieldErrors.privacy_consent = 'Conferma la presa visione dell’Informativa Privacy.';
      }

      if (Object.keys(this.fieldErrors).length > 0) {
        this.formError = 'Verifica i campi evidenziati prima di procedere.';
        return;
      }

      this.formLoading = true;
      try {
        const res = await fetch('api/contact.php', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': initialState.csrfToken || '',
          },
          body: JSON.stringify({
            ...this.form,
            csrf_token: initialState.csrfToken || '',
          }),
        });

        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
          if (data.errors && typeof data.errors === 'object') {
            this.fieldErrors = data.errors;
          }
          this.formError = data.message || 'Si è verificato un errore durante l’invio. Riprova tra qualche istante.';
          return;
        }

        this.formSuccess = data.message || 'Richiesta inviata correttamente.';
        this.form.name = '';
        this.form.email = '';
        this.form.phone = '';
        this.form.message = '';
        this.form.privacy_consent = false;
        this.form.company_website = '';
      } catch (_) {
        this.formError = 'Connessione non riuscita. Puoi contattarci direttamente al +39 0931 483018.';
      } finally {
        this.formLoading = false;
      }
    },
  }));

  Alpine.data('pqaHero', () => ({
    current: 0,
    paused: false,
    timer: null,
    slides: Array.isArray(initialState.heroSlides) && initialState.heroSlides.length > 0
      ? initialState.heroSlides
      : [
          {
            image: 'assets/img/hero-water.jpg',
            alt: 'Analisi chimica e microbiologica acque potabili e ricerca Legionella',
            caption: 'Qualità delle Acque & Ricerca Legionella',
          },
          {
            image: 'assets/img/hero-chem.jpg',
            alt: 'Strumentazione analitica di precisione e vetreria tarata in laboratorio',
            caption: 'Chimica Industriale & Merceologia',
          },
          {
            image: 'assets/img/hero-env.jpg',
            alt: 'Monitoraggio ambientale di acque marine, sedimenti e biota',
            caption: 'Ambiente, Sedimenti & Biota',
          },
        ],

    init() {
      const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (!reduced) {
        this.startTimer();
      }
    },

    startTimer() {
      this.stopTimer();
      this.timer = setInterval(() => {
        if (!this.paused) {
          this.next();
        }
      }, 6200);
    },

    stopTimer() {
      if (this.timer) {
        clearInterval(this.timer);
        this.timer = null;
      }
    },

    next() {
      this.current = (this.current + 1) % this.slides.length;
    },

    prev() {
      this.current = (this.current - 1 + this.slides.length) % this.slides.length;
    },

    goTo(index) {
      if (index >= 0 && index < this.slides.length) {
        this.current = index;
      }
    },
  }));
});
