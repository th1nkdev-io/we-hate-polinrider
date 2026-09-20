# Modèle de première notification (clients, collaborateurs)

À utiliser à l'étape 3 du [`playbook.md`](playbook.md). Objectif : prévenir **vite** et **factuellement**. Le retard de notification transforme un incident technique en problème juridique et commercial.

**Avant d'envoyer**
- Envoyer depuis une **adresse propre** (téléphone ou machine saine), jamais depuis une session ouverte sur la machine infectée.
- Ne pas minimiser, ne pas spéculer : ne mentionner que ce qui est établi. Compléter les crochets `[…]` ou les retirer.
- Si des **données personnelles** peuvent être concernées : le destinataire (responsable de traitement) doit évaluer sa notification à l'autorité de contrôle dans les **72 h** (RGPD) ; vous, sous-traitant, devez le prévenir **sans délai injustifié** pour qu'il tienne ce délai. Si l'enjeu est important, faire relire par un juriste.
- Un client qui n'a montré aucun IoC est **quand même concerné** si votre compte avait un accès en écriture à ses dépôts ou serveurs.

---

> **Objet :** Incident de sécurité — action requise sur [projet / serveur]
>
> Bonjour [Nom],
>
> Je vous informe sans délai d'un incident de sécurité me concernant. Mon poste de développement a été compromis par PolinRider, une campagne de supply-chain qui cible les environnements de développement et dérobe des identifiants.
>
> **Ce qui est susceptible d'être affecté chez vous :** [serveur / dépôt / accès concernés].
> **Période concernée :** du [date] au [date].
> **Nature des données potentiellement exposées :** [à compléter précisément, ou « en cours d'analyse »].
>
> **Mesures déjà prises :** révocation de l'ensemble de mes accès et jetons, isolation du poste concerné, [réinstallation du serveur / rotation des secrets / nettoyage des dépôts].
>
> **Ce que je vous recommande de faire maintenant :**
> 1. Changer les mots de passe des comptes administrateurs de [service].
> 2. Révoquer les accès que vous m'aviez accordés (je vous en demanderai de nouveaux une fois l'incident clos).
> 3. Vérifier les journaux de connexion sur la période indiquée.
> 4. Si des données personnelles sont concernées, évaluer votre obligation de notification (délai de 72 h).
>
> Je vous adresse un rapport détaillé sous [délai] et reste disponible immédiatement au [téléphone].
>
> [Signature]

---

**Message d'attente (première heure, si vous n'avez pas encore les détails)**

> Objet : Incident de sécurité en cours d'analyse — ne déployez rien
>
> Bonjour [Nom], une investigation de sécurité est en cours sur mon environnement de développement. Par précaution, ne déployez rien depuis les dépôts [liste] jusqu'à nouvel ordre. Je reviens vers vous sous 24 h avec un état précis et les actions à mener de votre côté.
