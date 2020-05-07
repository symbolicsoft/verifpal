Require Import PeanoNat String Coq.Numbers.DecimalString Decimal.
Local Open Scope nat_scope.

Inductive generator : Type :=
  | G.

Inductive constant : Type :=
  | Nil
  | value (s: string)
  | pub_key_c (G: generator) (exp: constant)
  | DH_c (G: generator) (exp1 exp2: constant)
  | ENC_c (key message : constant)
  | AEAD_ENC_c (key message ad: constant)
  | PKE_ENC_c (gk message: constant)
  | CONCAT2_c (a b: constant)
  | CONCAT3_c (a b c: constant) 
  | CONCAT4_c (a b c d: constant)
  | CONCAT5_c (a b c d e: constant)
  | HASH1_c (x: constant)
  | HASH2_c (x1 x2: constant)
  | HASH3_c (x1 x2 x3: constant)
  | HASH4_c (x1 x2 x3 x4: constant)
  | HASH5_c (x1 x2 x3 x4 x5: constant)
  | MAC_c (key message: constant)       
  | HKDF1_c (salt ikm info: constant)
  | HKDF2_c (salt ikm info: constant)
  | HKDF3_c (salt ikm info: constant)
  | HKDF4_c (salt ikm info: constant)
  | HKDF5_c (salt ikm info: constant)
  | PW_HASH_c (x: constant)
  | SIGN_c (k m: constant)
  | RINGSIGN_c (ka gkb gkc message: constant)
  | SHAMIR_SPLIT1_c (k: constant)
  | SHAMIR_SPLIT2_c (k: constant)
  | SHAMIR_SPLIT3_c (k: constant)
  | SHAMIR_JOIN_c (sa sb: constant)
  | INVALID (s: string)
  | NOT_FOUND
  | UNSUCCESSFUL
  | VALID.

Scheme Equality for constant.
 
Lemma string_equality: forall n m : string, (string_beq n m) = true <-> n = m.
Proof.
    intros; split.
    apply internal_string_dec_bl. 
    apply internal_string_dec_lb.
Qed.

Axiom  diffie_Hellman_commute : forall (G: generator) (a b: constant), DH_c G a b = DH_c G b a.

Axiom shamir_join : forall (a b c key : constant),
  a = SHAMIR_SPLIT1_c key ->
  b = SHAMIR_SPLIT2_c key ->
  c = SHAMIR_SPLIT3_c key -> 
  SHAMIR_JOIN_c a b = SHAMIR_JOIN_c b a /\
  SHAMIR_JOIN_c a c = SHAMIR_JOIN_c c a /\
  SHAMIR_JOIN_c b c = SHAMIR_JOIN_c c b.

Ltac bool_destruct_simp :=
  intros a b c; destruct a, b, c;
  simpl; try auto.

Lemma bool_commutative2: forall a b c : bool,
        a = true -> orb (b || a) c = true.
Proof.
  bool_destruct_simp.
Qed.

Lemma bool_commutative3: forall a b c : bool,
        a = true -> orb  (c || b) a = true.
Proof.
  bool_destruct_simp. 
Qed.

Definition  public_key(secret: constant) : constant := pub_key_c G secret.

Notation " G^( c )" := (public_key c) (at level 30, right associativity).
Notation "x =? y" := (constant_beq x y) (at level 70) : nat_scope.


Theorem pub_key: forall x: constant, G^( x ) = pub_key_c G x.
Proof.
  auto.
Qed.

Theorem pub_key_eq: forall x y: constant,
        x = y -> G^( x ) = G^( y ).
Proof.
   intros x y H.
   subst; auto.
Qed.

Lemma equality_generator : 
        forall (x : generator), generator_beq x x = true.
Proof.
    destruct x; auto.
Qed.

Lemma equal_constant_true : forall (c : constant),
       c =? c = true.
Proof.
    induction c; simpl; try firstorder.
    apply string_equality. reflexivity. 
    rewrite IHc. rewrite equality_generator; auto. 
    rewrite equality_generator, IHc1, IHc2; auto.
    rewrite IHc1, IHc2, IHc3, IHc4; auto. 
    rewrite IHc1, IHc2, IHc3, IHc4, IHc5; auto.
    rewrite IHc1, IHc2, IHc3, IHc4; auto.
    rewrite IHc1, IHc2, IHc3, IHc4, IHc5; auto.
    rewrite IHc1, IHc2, IHc3, IHc4; auto.
    apply string_equality. reflexivity.
Qed. 

Definition DH (c1 c2: constant): constant := DH_c G c1 c2. 

Lemma DH_commute :
  forall x y, DH x y = DH y x.
Proof.
  apply diffie_Hellman_commute.
Qed.

(* Encryption Primitives *)
Definition ENC(key plaintext: constant): constant := ENC_c key plaintext.

Definition DEC(key ciphertext: constant): constant :=
  match ciphertext with
    | ENC_c k m => match k =? key with
        | true => m
        | false => ENC_c k m
      end
    | _ => ciphertext
  end.

Theorem enc_dec: forall k m: constant, DEC k (ENC k m) = m.
Proof.
    unfold ENC, DEC;
    intros k m; rewrite equal_constant_true; try auto.
Qed.

Theorem enc_dec_2: forall k m c: constant, c = ENC k m -> m = DEC k c.
Proof.
    intros k m c H.
    rewrite -> H.
    rewrite -> enc_dec.
    reflexivity.
Qed.

Definition AEAD_ENC(key plaintext ad: constant): constant :=
        AEAD_ENC_c key plaintext ad.

Definition AEAD_DEC(key ciphertext ad: constant) : constant :=
  match ciphertext with 
    | AEAD_ENC_c k m ad' => match ad =? ad' with
        | true => match key =? k with
            | true => m
            | false => ciphertext
          end
        | false => INVALID "AEAD_DEC_fail_ad_mismatch"
      end
    | _ => ciphertext
  end.

Theorem aead_enc_dec: forall k m ad: constant,
        AEAD_DEC k (AEAD_ENC k m ad) ad = m.
Proof.
    unfold AEAD_ENC, AEAD_DEC;
    intros k m ad; rewrite equal_constant_true;
    rewrite equal_constant_true; try auto.
Qed.

Theorem aead_enc_dec_2: forall k m ad c: constant,
        c = AEAD_ENC k m ad -> m = AEAD_DEC k c ad.
Proof.
    intros k m ad c H.
    rewrite -> H.
    rewrite -> aead_enc_dec.
    reflexivity.
Qed.

Definition PKE_ENC(gkey plaintext: constant) : constant :=
        PKE_ENC_c gkey plaintext.

Definition PKE_DEC(key ciphertext: constant) : constant :=
  match ciphertext with
    | PKE_ENC_c gkey plaintext => 
      match (G^( key )) =? gkey with
        | true => plaintext
        | false => ciphertext
      end
    | _ => ciphertext
  end.

Theorem pke_enc_dec: forall k m: constant,
        PKE_DEC k (PKE_ENC (G^( k )) m) = m.
Proof.
    unfold PKE_ENC, PKE_DEC.
    intros k m; rewrite equal_constant_true; reflexivity.
Qed.

Theorem pke_enc_dec_2: forall k m c: constant,
        c = PKE_ENC (G^( k )) m -> m = PKE_DEC k c.
Proof.
    intros k m c H.
    rewrite -> H.
    rewrite -> pke_enc_dec. 
    reflexivity.
 Qed.


(* Hashing Primitives *)
Definition HASH1(a: constant) : constant := HASH1_c a.
Definition HASH2(a b : constant) : constant := HASH2_c a b.
Definition HASH3(a b c : constant) : constant := HASH3_c a b c.
Definition HASH4(a b c d : constant) : constant := HASH4_c a b c d.
Definition HASH5(a b c d e : constant) : constant := HASH5_c a b c d e.
Definition MAC(key message: constant) : constant := MAC_c key message.
Definition PW_HASH(a: constant) : constant := PW_HASH_c a.
Definition HKDF1 (salt ikm info: constant) := HKDF1_c salt ikm info.
Definition HKDF2 (salt ikm info: constant) := HKDF2_c salt ikm info.
Definition HKDF3 (salt ikm info: constant) := HKDF3_c salt ikm info.
Definition HKDF4 (salt ikm info: constant) := HKDF4_c salt ikm info.
Definition HKDF5 (salt ikm info: constant) := HKDF5_c salt ikm info.

(* Signature Primitives *)
Definition SIGN(key message: constant) : constant := SIGN_c key message.

Definition SIGNVERIF(gkey message signature: constant) : constant :=
  match gkey, signature with
    | pub_key_c _ exp, SIGN_c key m =>
      match andb (exp =? key) (message =? m) with
        | true => message
        | false => INVALID "SIGNVERIF_fail"
      end
    | _, _ => signature
  end.

Definition RINGSIGN(key_a gkey_b gkey_c message: constant) : constant :=
        RINGSIGN_c key_a gkey_b gkey_c message.

Definition RINGSIGNVERIF(ga gb gc m signature: constant): constant :=
  match signature with
    | RINGSIGN_c key_a b c message => match ga, gb, gc with 
        | pub_key_c _ exp_a, pub_key_c _ exp_b, pub_key_c _ exp_c =>
          match orb ((exp_a =? key_a) || (exp_b =? key_a))(exp_c =? key_a) with
            | true => m
            | false => INVALID "RINGSIGNVERIF_fail_unable_to_auth"
          end
        | _, _, _ =>  INVALID "RINGSIGNVERIF_fail_key_type_mismatch"
      end
    | _ => signature
  end.

Theorem ringsignverif_verif1: forall a b c m: constant,
          m = RINGSIGNVERIF (G^( a )) (G^( b )) (G^( c )) m (
            RINGSIGN a (G^( b )) (G^( c )) m).
Proof.
    unfold RINGSIGN, RINGSIGNVERIF.
    intros a b c m.
    simpl. rewrite equal_constant_true. simpl. reflexivity.
Qed.

Theorem ringsignverif_order_sign1: forall a b c m: constant,
        m = RINGSIGNVERIF (G^( a )) (G^( b )) (G^( c )) m (
          RINGSIGN a (G^( c )) (G^( b )) m).
Proof.
    unfold RINGSIGN, RINGSIGNVERIF.
    intros a b c m.
    simpl. rewrite equal_constant_true. simpl. reflexivity.
Qed.

Theorem ringsignverif_order_verif2: forall a b c m: constant,
        m = RINGSIGNVERIF (G^( b )) (G^( a )) (G^( c )) m (
          RINGSIGN a (G^( c )) (G^( b )) m).
Proof.
    unfold RINGSIGN, RINGSIGNVERIF.
    intros a b c m.
    simpl. rewrite equal_constant_true. simpl. rewrite bool_commutative2.
    reflexivity. reflexivity.
Qed.
  
Theorem ringsignverif_order_verif3: forall a b c m: constant,
        m = RINGSIGNVERIF (G^( b )) (G^( c )) (G^( a )) m (
          RINGSIGN a (G^( c )) (G^( b )) m).
Proof.
    unfold RINGSIGN, RINGSIGNVERIF.
    intros a b c m.
    simpl. rewrite equal_constant_true. simpl. rewrite bool_commutative3.
    reflexivity. reflexivity.
Qed.

(* Secret Sharing Primitives *)
Definition SHAMIR_SPLIT1 (k: constant) : constant := SHAMIR_SPLIT1_c k.
Definition SHAMIR_SPLIT2 (k: constant) : constant := SHAMIR_SPLIT2_c k.
Definition SHAMIR_SPLIT3 (k: constant) : constant := SHAMIR_SPLIT3_c k.

Definition SHAMIR_JOIN (sa sb: constant) : constant :=
  match sa,sb with
    | SHAMIR_SPLIT1_c ka, SHAMIR_SPLIT2_c kb => match ka =? kb with
        | true => ka
        | false => SHAMIR_JOIN_c sa sb
      end 
    | SHAMIR_SPLIT1_c ka, SHAMIR_SPLIT3_c kb => match ka =? kb with
        | true => ka
        | false => SHAMIR_JOIN_c sa sb
      end 
    | SHAMIR_SPLIT2_c ka, SHAMIR_SPLIT1_c kb => match ka =? kb with
        | true => ka
        | false => SHAMIR_JOIN_c sa sb
      end 
    | SHAMIR_SPLIT2_c ka, SHAMIR_SPLIT3_c kb => match ka =? kb with
        | true => ka
        | false => SHAMIR_JOIN_c sa sb
      end 
    | SHAMIR_SPLIT3_c ka, SHAMIR_SPLIT1_c kb => match ka =? kb with
        | true => ka
        | false => SHAMIR_JOIN_c sa sb
      end 
    | SHAMIR_SPLIT3_c ka, SHAMIR_SPLIT2_c kb => match ka =? kb with
        | true => ka
        | false => SHAMIR_JOIN_c sa sb
      end 
    | _, _ => SHAMIR_JOIN_c sa sb
  end.

(* Lemma shamir_join_commute : forall (a b : constant), SHAMIR_JOIN_c a b = SHAMIR_JOIN_c b a.
Proof.

Qed. *)

(* Core Primitives *)
Definition ASSERT (c1 c2: constant) : constant :=
  match c1 =? c2 with
    | true => VALID
    | false => INVALID "ASSERT_fail"
  end.

Definition CONCAT2 (c1 c2: constant) : constant := CONCAT2_c c1 c2.
Definition CONCAT3 (c1 c2 c3: constant) : constant := CONCAT3_c c1 c2 c3.
Definition CONCAT4 (c1 c2 c3 c4: constant) : constant := CONCAT4_c c1 c2 c3 c4.
Definition CONCAT5 (c1 c2 c3 c4 c5: constant) : constant := CONCAT5_c c1 c2 c3 c4 c5.

Definition SPLIT1 (c: constant) : constant :=
  match c with
    | CONCAT2_c c' _ => c'
    | CONCAT3_c c' _ _ => c'
    | CONCAT4_c c' _ _ _ => c'
    | CONCAT5_c c' _ _ _ _ => c'
    | _ => INVALID("Attempting to use SPLIT1 with an incompatible argument")
  end.

Definition SPLIT2 (c: constant) : constant :=
  match c with
    | CONCAT2_c _ c' => c'
    | CONCAT3_c _ c' _ => c'
    | CONCAT4_c _ c' _ _ => c'
    | CONCAT5_c _ c' _ _ _ => c'
    | _ => INVALID("Attempting to use SPLIT2 with an incompatible argument")
  end.

Definition SPLIT3 (c: constant) : constant :=
  match c with
    | CONCAT3_c _ _ c' => c'
    | CONCAT4_c _ _ c' _ => c'
    | CONCAT5_c _ _ c' _ _ => c'
    | _ => INVALID("Attempting to use SPLIT3 with an incompatible argument")
  end.

Definition SPLIT4 (c: constant) : constant :=
  match c with
    | CONCAT4_c _ _ _ c' => c'
    | CONCAT5_c _ _ _ c' _ => c'
    | _ => INVALID("Attempting to use SPLIT4 with an incompatible argument")
  end.

Definition SPLIT5 (c: constant) : constant :=
  match c with
    | CONCAT5_c _ _ _ _ c' => c'
    | _ => INVALID("Attempting to use SPLIT5 with an incompatible argument")
  end.

(*end of primitives*)
Inductive qualifier : Type :=
  | public
  | private
  | password.

Inductive declaration : Type :=
  | assignment
  | knows
  | generates.

Inductive guard_state : Type :=
  | guarded
  | unguarded.

Inductive leak_state : Type :=
  | leaked
  | not_leaked.

Inductive constant_meta: Type :=
  | constant_meta_c (c: constant) (d: declaration) (q: qualifier)
    (created_by name: string) (l: leak_state)
  | constant_meta_invalid (code: string).

Fixpoint constant_meta_constructor (c: constant) (d: declaration)
        (q: qualifier) (created_by name: string) :=
  match eqb created_by "", eqb name "" with
    | true, true => constant_meta_invalid 
      "constant_meta must have an non empty value for created_by and name."
    | true, false => constant_meta_invalid
      "constant_meta must have an non empty value for created_by."
    | false, true => constant_meta_invalid
      "constant_meta must have an non empty value for name."
    | false, false => constant_meta_c c d q created_by name not_leaked
  end.

Fixpoint get_name_constant_meta (c: constant_meta) : string :=
  match c with
    | constant_meta_invalid code => code
    | constant_meta_c _ _ _ _ name _ => name
  end.

Fixpoint equal_constant_meta (a b: constant_meta) : bool :=
  match a,b with
    | constant_meta_c c1 _ _ _ _ _, constant_meta_c c2 _ _ _ _ _ => c1 =? c2
    | _, _ => false
  end.

Fixpoint leak_constant_meta (cm: constant_meta) : constant_meta :=
  match cm with
    | constant_meta_invalid code => constant_meta_invalid (
      "Attempting to leak invalid constant_meta; " ++ code)
    | constant_meta_c c d q created_by name _
      => constant_meta_c c d q created_by name leaked
  end.

Inductive principal_knowledge: Type :=
  | principal_knowledge_empty
  | principal_knowledge_invalid (code: string)
  | principal_knowledge_c (c: constant_meta) (next: principal_knowledge).

Fixpoint principal_knowledge_constructor (cm: constant_meta)
        (next: principal_knowledge) : principal_knowledge :=
  match cm with
    | constant_meta_invalid code => principal_knowledge_invalid
      "Attempting to construct principal_knowledge using invalid constant_meta"
    | constant_meta_c _ _ _ _ _ _ => match next with
        | principal_knowledge_invalid code => principal_knowledge_invalid
          "Attempting to construct principal_knowledge using invalid provided next principal_knowledge"
        | _ => principal_knowledge_c cm next
      end
  end.

Fixpoint push_pk (pk: principal_knowledge) 
        (cm: constant_meta) : principal_knowledge :=
  match pk with
    | principal_knowledge_invalid code => principal_knowledge_invalid (
      "Attempting to push constant_meta to invalid principal_knowledge; " ++ code)
    | _ => principal_knowledge_constructor cm pk
  end.

Fixpoint get_constant_meta_by_name_pk (pk: principal_knowledge)
        (name: string) : constant_meta :=
  match pk with
    | principal_knowledge_invalid code => constant_meta_invalid (
      "Attempting to get constant_meta from invalid principal_knowledge; " ++ code)
    | principal_knowledge_empty => constant_meta_invalid "Value not found"
    | principal_knowledge_c c next => match eqb name "" with
        | true => constant_meta_invalid 
          "Attempting to get a constant_meta with an empty string as its name"
        | false => match eqb (get_name_constant_meta c) name with
            | true => c
            | false => get_constant_meta_by_name_pk next name
          end
      end
  end.

Fixpoint search_constant_meta_by_name_pk (pk: principal_knowledge)
        (name: string) : bool :=
  match pk with
    | principal_knowledge_invalid code => false
    | principal_knowledge_empty => false
    | principal_knowledge_c c next => match eqb name "" with
        | true => false
        | false => match eqb (get_name_constant_meta c) name with
            | true => true
            | false => search_constant_meta_by_name_pk next name
          end
      end
  end.

Fixpoint remove_constant_meta_pk (pk: principal_knowledge)
        (name: string) : principal_knowledge :=
  match pk with
    | principal_knowledge_empty => pk
    | principal_knowledge_invalid code => principal_knowledge_invalid (
      "Attempting to remove constant_meta from invalid principal_knowledge; " ++ code)
    | principal_knowledge_c cm next => match eqb name "" with
        | true => principal_knowledge_invalid
          "Attempting to remove a constant_meta with an empty string as its name"
        | false => match eqb name (get_name_constant_meta cm) with
            | true => next
            | false => principal_knowledge_constructor cm (
              remove_constant_meta_pk next name)
          end
      end
  end.

Fixpoint update_constant_meta_pk (pk: principal_knowledge)
        (cm: constant_meta): principal_knowledge :=
  match pk with
    | principal_knowledge_invalid code => principal_knowledge_invalid (
      "Attempting to update a constant_meta in an invalid principal_knowledge; " ++ code)
    | principal_knowledge_empty => principal_knowledge_invalid
      "constant_meta not found"
    | principal_knowledge_c _ _ => match cm with
        | constant_meta_invalid _ => principal_knowledge_invalid
          "Attempting to update a constant_meta using an invalid principal"
        | constant_meta_c _ _ _ _ _ _ => principal_knowledge_constructor cm (
          remove_constant_meta_pk pk (get_name_constant_meta cm))
      end
  end.

Fixpoint leak_constant_meta_pk (pk: principal_knowledge)
        (name: string) : principal_knowledge :=
  match pk with
    | principal_knowledge_invalid code => principal_knowledge_invalid (
      "Attempting to leak constant_meta in invalid principal_knowledge; " ++ code)
    | principal_knowledge_empty => principal_knowledge_invalid
      "Attempting to leak constant_meta in empty principal_knowledge"
    | principal_knowledge_c _ _ => update_constant_meta_pk pk (
      leak_constant_meta(get_constant_meta_by_name_pk pk name))
  end.

Inductive principal : Type :=
  | principal_invalid (code: string)
  | principal_c (name: string) (pk: principal_knowledge).

Fixpoint principal_constructor (name: string)
        (pk: principal_knowledge) : principal :=
  match eqb name "" with
    | true => principal_invalid
      "Attempt to construct a principal without a name."
    | false => principal_c name pk
  end.

Fixpoint teach_principal (p: principal) (cm: constant_meta) : principal :=
  match p with
    | principal_invalid _ => p
    | principal_c name knowledge => principal_constructor name (
      push_pk knowledge cm)
  end.

Fixpoint generate_value (p: principal) (s: string) : principal :=
  match eqb "" s with
    | true => principal_invalid
      "Generated value must have a non empty string as its name."
    | false => match p with
        | principal_invalid _ => p
        | principal_c name _ => teach_principal p (
          constant_meta_constructor (value s) generates private name s)
      end
  end.

Fixpoint know_value (p: principal)
        (s: string) (q: qualifier) : principal :=
  match eqb "" s with
    | true => principal_invalid
      "Value to be known must have a non empty string as its name."
    | false => match p with
        | principal_invalid _ => p
        | principal_c name _ => teach_principal p (
          constant_meta_constructor (value s) knows q name s)
      end
  end.

Fixpoint assign_value (p: principal)
        (c: constant) (s: string) : principal :=
  match eqb "" s with
    | true => principal_invalid
      "Assigned value must have a non empty string as its name."
    | false => match p with
        | principal_invalid code => p
        | principal_c name _ => teach_principal p (
          constant_meta_constructor c assignment private name s)
      end
  end.

Fixpoint get_name_principal (p: principal) : string :=
  match p with
    | principal_invalid code => code
    | principal_c name _ => name
  end.

Fixpoint get_constant_meta_by_name_principal (p: principal)
        (name: string) : constant_meta :=
  match eqb "" name with
    | true => constant_meta_invalid
      "Attempting to look for a value with an empty string as its name"
    | false => match p with
        | principal_invalid _ => constant_meta_invalid "Value not found."
        | principal_c _ k => get_constant_meta_by_name_pk k name
      end
  end.

Fixpoint leak_value (p: principal) (value_name: string) : principal :=
  match eqb "" value_name with
    | true => principal_invalid
      "Attepmting to leak a value with an invalid name."
    | false => match p with
        | principal_invalid code => principal_invalid (
          "Attempting to leak a value in an invalid principal; " ++ code)
        | principal_c principal_name pk => principal_constructor principal_name (
          leak_constant_meta_pk pk value_name)
      end
  end.

Fixpoint get (p: principal) (name: string) : constant :=
  match (get_constant_meta_by_name_principal p name) with
    | constant_meta_invalid code => INVALID code
    | constant_meta_c c' _ _ _ _ _ => c'
  end.

Inductive principal_list : Type :=
  | principal_list_invalid (code: string)
  | principal_list_empty
  | principal_list_c (p: principal) (next: principal_list).

Fixpoint principal_list_constructor (p: principal)
        (next: principal_list) : principal_list :=
  match p with
    | principal_invalid code => principal_list_invalid (
      "Cannot construct principal_list using invalid principal; " ++ code)
    | principal_c _ _ => match next with 
        | principal_list_invalid code => principal_list_invalid (
          "Cannot construct principal_list using invalid next principal_list; " ++ code)
        | _ => principal_list_c p next
      end
  end.

Fixpoint add_principal (list: principal_list)
        (p: principal) : principal_list :=
  match list with
    | principal_list_invalid code => principal_list_invalid (
      "Cannot add principal to invalid list; " ++ code)
    | principal_list_empty => principal_list_constructor p list
    | principal_list_c _ next => principal_list_constructor p list
  end.

Fixpoint remove_principal (list: principal_list)
        (name: string) : principal_list :=
  match list with
    | principal_list_invalid code => principal_list_invalid (
      "Attempting to remove a principal from an invalid principal_list; " ++ code)
    | principal_list_empty => principal_list_invalid
      "Principal not found"
    | principal_list_c p next => match eqb name "" with
        | true => principal_list_invalid 
          "Attempting to remove a principal with an empty string as its name"
        | false => match eqb name (get_name_principal p) with
            | true => next
            | false => principal_list_constructor p (
              remove_principal next name)
          end
      end
  end.
Fixpoint update_principal (list: principal_list)
        (p: principal): principal_list :=
  match list with
    | principal_list_invalid code => principal_list_invalid (
      "Attempting to update a principal in an invalid principal_list; " ++ code)
    | principal_list_empty => principal_list_invalid "Principal not found"
    | principal_list_c _ _ => match p with
        | principal_invalid _ => principal_list_invalid
          "Attempting to update a principal_list using an invalid principal"
        | principal_c _ _ => principal_list_constructor p (
          remove_principal list (get_name_principal p))
      end
  end.

Fixpoint get_principal_by_name_principal_list (list: principal_list)
        (name: string) : principal :=
  match list with
    | principal_list_invalid code => principal_invalid (
      "Attempting to get a principal from an invalid principal_list; " ++ code)
    | principal_list_empty => principal_invalid "Principal not found"
    | principal_list_c p list' => match eqb name "" with
        | true => principal_invalid
          "The provided name for the principal cannot be empty"
        | false => match eqb (get_name_principal p) name with
            | true => p
            | false => get_principal_by_name_principal_list list' name
          end
      end
  end.

Fixpoint teach_principal_principal_list (list: principal_list)
        (principal_name: string) (cm: constant_meta) : principal_list :=
  match cm with
    | constant_meta_invalid code => principal_list_invalid (
      "Attempting to teach an invalid constant_meta to a principal; " ++ code)
    | constant_meta_c _ _ _ _ _ _ => match eqb principal_name "" with
        | true => principal_list_invalid
          "The provided name for the principal cannot be empty"
        | false => match list with
            | principal_list_invalid code => principal_list_invalid (
              "Attempting to teach a principal in an invalid principal_list; " ++ code)
            | principal_list_empty => add_principal list (
              teach_principal (
              principal_constructor principal_name principal_knowledge_empty)
              cm)
            | principal_list_c p list' => update_principal list (
              teach_principal (
              get_principal_by_name_principal_list list principal_name)
              cm)
          end
      end
  end.

Fixpoint get_constant_meta_by_name_principal_list (list: principal_list) (name: string) : constant_meta :=
  match eqb "" name with
    | true => constant_meta_invalid "Name provided to get_constant_meta_by_name_principal_list can not be empty"
    | false => match list with
        | principal_list_invalid code => constant_meta_invalid "Attempting to get_constant_meta_by_name_principal_list from an in valid principal list"
        | principal_list_empty => constant_meta_invalid ("Constant: " ++ name ++ " not Found; get_constant_meta_by_name_principal_list")
        | principal_list_c principal next => match get_constant_meta_by_name_principal principal name with
            | constant_meta_c _ _ _ _ _ _ => get_constant_meta_by_name_principal principal name
            | _ => get_constant_meta_by_name_principal_list next name
          end
      end
  end.

Inductive message : Type :=
  | message_c (from to value_name: string) (g: guard_state)
  | message_invalid (code: string).

Fixpoint message_constructor (from to value_name: string) (g: guard_state) :=
  match eqb "" from, eqb "" to, eqb "" value_name with
    | true, _, _ => message_invalid "The value of from cannot be empty"
    | _, true, _ => message_invalid "The value of to cannot be empty"
    | _, _, true => message_invalid "The value of value_name cannot be empty"
    | false, false, false => message_c from to value_name g
  end.

Inductive message_list : Type :=
  | message_list_invalid (code: string)
  | message_list_empty
  | message_list_c (m: message) (next: message_list).

Fixpoint message_list_constructor (m: message) : message_list :=
  match m with
    | message_invalid _ => message_list_invalid
      "Attempting to construct message_list using an invalid message"
    | message_c _ _ _ _ => message_list_c m message_list_empty
  end.

Fixpoint add_message_to_list (list: message_list)
        (m: message) : message_list :=
  match m with
    | message_invalid _ => message_list_invalid
      "Attempting to add invalid message to list"
    | message_c _ _ _ _ => match list with
        | message_list_invalid _ => message_list_invalid
          "Attempting to add message to invalid message_list"
        | message_list_empty => message_list_constructor m
        | message_list_c _ next => add_message_to_list next m
      end
  end.

Inductive knowledgemap : Type :=
  | knowledgemap_invalid (code: string)
  | knowledgemap_c (list: principal_list) (messages: message_list).

Fixpoint knowledgemap_constructor (principal_name: string) : knowledgemap :=
  match eqb principal_name "" with
    | true => knowledgemap_invalid
      "Attempting to construct knowledge map with empty principal name"
    | false => knowledgemap_c (principal_list_constructor (
      principal_constructor principal_name principal_knowledge_empty)
      principal_list_empty) message_list_empty
  end.

Fixpoint knowledgemap_constructor_alternative (pl: principal_list)
        (ml: message_list) : knowledgemap :=
  match pl with
    | principal_list_invalid code => knowledgemap_invalid (
        "Attempting to contruct knowledgemap using invalid principal_list" ++ code)
        | _ => match ml with
        | message_list_invalid code => knowledgemap_invalid (
          "Attempting to contruct knowledgemap using invalid message_list" ++ code)
        | _ => knowledgemap_c pl ml
      end
  end.

Fixpoint add_principal_knowledgemap (k: knowledgemap)
        (name: string) : knowledgemap :=
  match k with
    | knowledgemap_invalid code => knowledgemap_invalid (
      "Attempting to add principal to invalid knowledgemap; " ++ code)
    | knowledgemap_c list m => knowledgemap_c (add_principal list (
      principal_constructor name principal_knowledge_empty)) m
  end.

Fixpoint get_principal_knowledgemap (k: knowledgemap)
        (name: string) : principal :=
  match k with
    | knowledgemap_invalid code => principal_invalid (
      "Attempting to get principal from invalid knowledgemap; " ++ code)
    | knowledgemap_c list _ => get_principal_by_name_principal_list list name
  end.

Fixpoint get_principal_knowledge_knowledgemap (k: knowledgemap)
        (name: string) : principal_knowledge :=
  match get_principal_knowledgemap k name with
    | principal_invalid code => principal_knowledge_invalid (
      "Attempting to get principal_knowledge from invalid principal; " ++ code)
    | principal_c _ pk => pk
  end.

Fixpoint get_constant_meta_from_principal_by_name_knowledgemap (k: knowledgemap)
        (principal_name constant_name: string) : constant_meta :=
    match eqb "" principal_name, eqb "" constant_name with
    | true, true => constant_meta_invalid
      "Invalid principal_name and constant_name provided to get_constant_meta_from_principal_by_name"
    | true, false => constant_meta_invalid
      "Invalid principal_name provided to get_constant_meta_from_principal_by_name"
    | false, true => constant_meta_invalid
      "Invalid constant_name provided to get_constant_meta_from_principal_by_name"   
    | false, false => get_constant_meta_by_name_pk (
      get_principal_knowledge_knowledgemap k principal_name) constant_name
  end.

Fixpoint get_constant_meta_by_name_knowledgemap (k: knowledgemap)
        (name: string) : constant_meta :=
    match eqb "" name with
    | true => constant_meta_invalid
      "Invalid constant_name provided to get_constant_meta_from_principal_by_name"   
    | false => match k with
        | knowledgemap_invalid code => constant_meta_invalid (
          "Attempting to get constant_meta from invalid knowledgemap; " ++ code)
        | knowledgemap_c pl _ => get_constant_meta_by_name_principal_list pl name
      end
  end.

Fixpoint update_principal_knowledgemap (k: knowledgemap)
        (p: principal) : knowledgemap :=
  match k with
    | knowledgemap_invalid code => knowledgemap_invalid (
      "Attempting to update principal in invalid knowledgemap; " ++ code)
    | knowledgemap_c list m => knowledgemap_c (update_principal list p) m
  end.

Fixpoint add_message_knowledgemap (k: knowledgemap)
        (m: message) : knowledgemap :=
  match k with
    | knowledgemap_invalid code => knowledgemap_invalid (
      "Attempting to add message to invalid knowledgemap; " ++ code)
    | knowledgemap_c list messages => knowledgemap_c list (
      add_message_to_list messages m)
  end.

Fixpoint send_message (s: knowledgemap): knowledgemap :=
  match s with
    | knowledgemap_invalid _ => knowledgemap_invalid
      "Attempting to send a message using an invalid knowledgemap"
    | knowledgemap_c list messages => match messages with
        | message_list_invalid _ => knowledgemap_invalid
          "Invalid message list"
        | message_list_empty => s
        | message_list_c m next => match m with 
            | message_invalid _ => knowledgemap_invalid
              "Attempting to send an invalid message"
            | message_c from to value_name g =>
              match get_principal_by_name_principal_list list from with
                | principal_invalid code => knowledgemap_invalid (
                  "The sender provided is not valid; " ++ code)
                | principal_c _ sender_pk => 
                  match get_constant_meta_by_name_pk sender_pk value_name with
                    | constant_meta_invalid code => knowledgemap_invalid (
                      "The sender does now list know the value being sent; " ++ code)
                    | constant_meta_c _ _ _ _ _ _
                      => match get_principal_by_name_principal_list list to with
                        | principal_invalid code => knowledgemap_invalid (
                          "The recipient provided is not valid; " ++ code)
                        | principal_c _ recipient_pk => knowledgemap_c (
                          teach_principal_principal_list list to (
                          get_constant_meta_by_name_pk sender_pk value_name)
                          ) next
                      end
                  end
              end
          end
      end
  end.

Inductive attacker_type : Type :=
  | passive
  | active.

Inductive mutability : Type :=
  | mutable
  | immutable.

Inductive attacker_knowledge : Type :=
  | attacker_knowledge_invalid (code: string)
  | attacker_knowledge_empty
  | attacker_knowledge_c (cm: constant_meta)
    (m: mutability) (next: attacker_knowledge).

Fixpoint attacker_knowledge_constructor (cm: constant_meta)
        (m: mutability) (next: attacker_knowledge) : attacker_knowledge :=
  match cm with
    | constant_meta_invalid code => attacker_knowledge_invalid (
      "Attempting to construct attacker_knowledge using invalid constant_meta; " ++ code)
    | constant_meta_c _ _ _ _ _ _ => match next with
        | attacker_knowledge_invalid code => attacker_knowledge_invalid
          "Attempting to construct attacker_knowledge using invalid provided next attacker_knowledge"
        | _ => attacker_knowledge_c cm m next
      end
  end.

Fixpoint push_ak (ak: attacker_knowledge)
        (cm: constant_meta) (m: mutability) : attacker_knowledge :=
  match ak with
    | attacker_knowledge_invalid code => attacker_knowledge_invalid (
      "Attempting to push constant_meta to invalid attacker_knowledge; " ++ code)
    | _ => attacker_knowledge_constructor cm m ak
  end.

Fixpoint get_constant_meta_by_name_ak (ak: attacker_knowledge)
        (name: string) : constant_meta :=
  match ak with
    | attacker_knowledge_invalid code => constant_meta_invalid (
      "Attempting to get constant_meta from invalid attacker_knowledge; " ++ code)
    | attacker_knowledge_empty => constant_meta_invalid "Value not found"
    | attacker_knowledge_c c _ next => match eqb name "" with
        | true => constant_meta_invalid
          "Attempting to get a constant_meta with an empty string as its name"
        | false => match eqb (get_name_constant_meta c) name with
            | true => c
            | false => get_constant_meta_by_name_ak next name
          end
      end
  end.

Fixpoint search_constant_meta_by_name_ak (ak: attacker_knowledge)
        (name: string) : bool :=
  match ak with
    | attacker_knowledge_invalid code => false
    | attacker_knowledge_empty => false
    | attacker_knowledge_c cm _ next => match eqb name "" with
        | true => false
        | false => match eqb (get_name_constant_meta cm) name with
            | true => true
            | false => search_constant_meta_by_name_ak next name
          end
      end
  end.

Fixpoint get_equivalent_constant_ak (ak: attacker_knowledge) (c: constant) : constant :=
  match ak with
    | attacker_knowledge_invalid _ => INVALID "Attempting to get equivalent constant in invalid attacker"
    | attacker_knowledge_empty => NOT_FOUND
    | attacker_knowledge_c cm _ next => match cm with
        | constant_meta_invalid _ => INVALID "Attempting to get equivalent constant in invalid attacker"
        | constant_meta_c const _ _ _ _ _ => match const =? c with
            | true => const
            | false => get_equivalent_constant_ak next c
          end
      end
  end.

Fixpoint can_mutate_ak (ak: attacker_knowledge) (name: string) : bool :=
  match ak with
    | attacker_knowledge_invalid code => false
    | attacker_knowledge_empty => false
    | attacker_knowledge_c c m next => match eqb name "" with
        | true => false
        | false => match eqb (get_name_constant_meta c) name with
            | false => search_constant_meta_by_name_ak next name
            | true => match m with
                | mutable => true
                | immutable => false
              end
          end
      end
  end.

Fixpoint length_ak (ak: attacker_knowledge) : nat :=
  match ak with
    | attacker_knowledge_c _ _ next => S (length_ak next)
    | _ => 0
  end.

Inductive attacker : Type :=
  | attacker_invalid (code: string)
  | attacker_c (t: attacker_type) (learn_counter: uint) (ak: attacker_knowledge).

Fixpoint attacker_constructor (type: attacker_type) (learn_counter: uint)
        (knowledge: attacker_knowledge) : attacker := attacker_c type learn_counter knowledge.

Fixpoint search_cm_attacker (a: attacker) (cm: constant_meta) : bool :=
  match a with
    | attacker_invalid _ => false
    | attacker_c _ _ ak => search_constant_meta_by_name_ak ak (
      get_name_constant_meta cm)
  end.
  
Fixpoint search_by_name_attacker (a: attacker) (name: string) : bool :=
  match a with
    | attacker_invalid _ => false
    | attacker_c _ _ ak => search_constant_meta_by_name_ak ak name
   end.

Fixpoint get_equivalent_constant_attacker (a: attacker) (c: constant) : constant :=
  match a with
    | attacker_invalid code => INVALID (
      "Attempting to get_equivalent_constant_attacker from an invalid attacker; " ++ code)
    | attacker_c _ _ ak => get_equivalent_constant_ak ak c
  end.

Fixpoint can_learn_attacker (a: attacker) (cm: constant_meta) : bool :=
  match a with
    | attacker_invalid _ => false
    | attacker_c _ _ ak => match search_cm_attacker a cm with
        | true => false
        | false => match cm with
            | constant_meta_invalid _ => false
            | constant_meta_c _ _ q _ _ l => match l, q with
                | leaked, _ => true
                | _, public => true
                | _, _ => false
              end
          end
      end
  end.

Fixpoint absorb_constant_meta_attacker (a: attacker)
        (cm: constant_meta) (m: mutability) : attacker :=
  match a with
    | attacker_invalid _ => attacker_invalid
      "Attempting to teach an invalid Attacker"
    | attacker_c t lc ak => attacker_constructor t lc (push_ak ak cm m)
  end.

Fixpoint absorb_principal_knowledge_attacker (a: attacker)
        (pk: principal_knowledge) : attacker :=
  match a with
    | attacker_invalid _ => attacker_invalid
      "Attempting to teach an invalid Attacker"
    | attacker_c _ _ ak => match pk with
        | principal_knowledge_invalid _ => attacker_invalid
          "Attempting to teach invalid principal knowledge to attacker"
        | principal_knowledge_empty => a
        | principal_knowledge_c cm pk' => match can_learn_attacker a cm with
            | true => absorb_principal_knowledge_attacker (
              absorb_constant_meta_attacker a cm immutable) pk'
            | false => absorb_principal_knowledge_attacker a pk'
          end
      end
  end.

Fixpoint absorb_message_attacker (a: attacker)
        (m: message) (k: knowledgemap) : attacker :=
  match a with
    | attacker_invalid code => attacker_invalid (
      "Attempting to teach invalid attacker; " ++ code)
    | attacker_c type _ ak => match m with 
        | message_invalid code => attacker_invalid (
          "Attempting to absord an invalid message" ++ code)
        | message_c from _ value_name g => match k with
            | knowledgemap_invalid code => attacker_invalid (
              "Attempting to send a message using an invalid knowledgemap" ++ code)
            | knowledgemap_c _ _ => match type, g with
                | active, unguarded => absorb_constant_meta_attacker a (
                  get_constant_meta_from_principal_by_name_knowledgemap 
                  k from value_name)
                  mutable
                | _, _ => absorb_constant_meta_attacker a (
                  get_constant_meta_from_principal_by_name_knowledgemap
                  k from value_name)
                  immutable
              end
          end
      end
  end.

Fixpoint absorb_principal_list_attacker (a: attacker)
        (pl: principal_list) : attacker :=
  match a with
    | attacker_invalid code => attacker_invalid (
      "Attempting to teach invalid attacker; " ++ code)
    | attacker_c t _ ak => match pl with
        | principal_list_invalid code =>  attacker_invalid (
          "Attempting to teach attacker using invalid principal_list; " ++ code)
        | principal_list_empty => a
        | principal_list_c principal next => match principal with
            | principal_invalid code =>  attacker_invalid (
              "Attempting to teach attacker using invalid principal; " ++ code)
            | principal_c _ pk => absorb_principal_list_attacker (
              absorb_principal_knowledge_attacker a pk) next
          end
      end
  end.

Fixpoint absorb_message_list_attacker (a: attacker)
        (ml: message_list) (k: knowledgemap) : attacker :=
  match a with
    | attacker_invalid code => attacker_invalid (
      "Attempting to teach invalid attacker; " ++ code)
    | attacker_c t _ ak => match ml with
        | message_list_invalid code =>  attacker_invalid (
          "Attempting to teach attacker using invalid message_list; " ++ code)
        | message_list_empty => a
        | message_list_c message next => match message with
            | message_invalid code =>  attacker_invalid (
              "Attempting to teach attacker an invalid message; " ++ code)
            | message_c _ _ _ _ => absorb_message_list_attacker (
              absorb_message_attacker a message k) next k
          end
      end
  end.

Fixpoint absorb_knowledgemap_attacker (a: attacker)
        (k: knowledgemap) : attacker :=
  match a with
    | attacker_invalid code => attacker_invalid (
      "Attempting to teach invalid attacker; " ++ code)
    | attacker_c t _ ak => match k with
        | knowledgemap_invalid code => attacker_invalid (
          "Attempting to absorb invalid knowledgemap; " ++ code)
        | knowledgemap_c pl ml => absorb_message_list_attacker (
          absorb_principal_list_attacker a pl) ml k
      end
  end.

Fixpoint learn_constant (a: attacker) (c: constant) : attacker :=
  match a with
    | attacker_invalid code => attacker_invalid (
      "Attempting to learn_constant to using invalid attacker; " ++ code)
    | attacker_c type count ak => match ak with
        | attacker_knowledge_invalid code => attacker_invalid (
          "Attempting to learn_consting using an attacker that has an invalid attacker knowledge; " ++ code)
        | _ => match get_equivalent_constant_ak ak c with 
            | NOT_FOUND => a
            | INVALID code => attacker_invalid(
              "get_equivalent_constant_ak returned invalid in learn_constant; " ++ code)
            | _ => attacker_constructor type (Little.succ count) (
              push_ak ak (constant_meta_constructor c knows public "Attacker" (
              append ("unnamed_") ((NilEmpty.string_of_uint(Little.succ count))%string)))
              immutable)
          end
      end
  end.

Fixpoint learn_concat (a: attacker) (concat: constant): attacker :=
  match a with
    | attacker_invalid code => attacker_invalid (
      "Attempting to apply learn_concat on invalid attacker; " ++ code)
        | attacker_c _ _ _ => match concat with
        | CONCAT2_c _ _ => learn_constant (learn_constant a (SPLIT1 concat)) (SPLIT2 concat)
        | CONCAT3_c _ _ _ => learn_constant (learn_constant (learn_constant a (SPLIT1 concat)) (SPLIT2 concat)) (SPLIT3 concat)
        | CONCAT4_c _ _ _ _ => learn_constant (learn_constant (learn_constant (learn_constant a (SPLIT1 concat)) (SPLIT2 concat)) (SPLIT3 concat)) (SPLIT4 concat)
        | CONCAT5_c _ _ _ _ _ =>  learn_constant (learn_constant (learn_constant (learn_constant (learn_constant a (SPLIT1 concat)) (SPLIT2 concat)) (SPLIT3 concat)) (SPLIT4 concat)) (SPLIT5 concat)
        | _ =>attacker_invalid "Attempting to apply learn_concat on attacker using constant that isnt of type CONCAT"
      end
  end.

Fixpoint learn_enc (a: attacker) (c: constant): attacker :=
  match a with
    | attacker_invalid code => attacker_invalid (
      "Attempting to apply learn_concat on invalid attacker; " ++ code)
      | attacker_c _ _ ak => match c with
          | ENC_c k m =>  learn_constant a (DEC (get_equivalent_constant_ak ak k) c)
          | _ => attacker_invalid "Attempting to apply learn_concat on attacker using constant that isnt of subtype ENC_c"
      end
  end.

Fixpoint learn_aead_enc (a: attacker) (c: constant): attacker :=
  match a with
    | attacker_invalid code => attacker_invalid (
      "Attempting to apply learn_concat on invalid attacker; " ++ code)
      | attacker_c _ _ ak => match c with
          | AEAD_ENC_c k m ad =>  learn_constant a (AEAD_DEC (get_equivalent_constant_ak ak k) c (get_equivalent_constant_ak ak ad))
          | _ => attacker_invalid "Attempting to apply learn_aead_enc on attacker using constant that isnt of subtype AEAD_ENC_c"
      end
  end.

Fixpoint learn_pke_enc (a: attacker) (c: constant): attacker :=
  match a with
    | attacker_invalid code => attacker_invalid (
      "Attempting to apply learn_concat on invalid attacker; " ++ code)
      | attacker_c _ _ ak => match c with
          | PKE_ENC_c k m =>  match k with
              | pub_key_c _ sk => learn_constant a (PKE_DEC sk c)
              | _ => attacker_invalid "Attempting to apply learn_concat on attacker using PKE_ENC_c that was not encrypted with a public_key_c object"
            end
          | _ => attacker_invalid "Attempting to apply learn_concat on attacker using constant that isnt of subtype PKE_ENC_c"
        end
  end.


Fixpoint reconstruct_into_c (a: attacker) (c: constant) : constant :=
  match a with
    | attacker_invalid code => INVALID (
      "Attempting to reconstruct_into_c using an invalid attacker" ++ code)
    | attacker_c type lc ak => match ak with
        | attacker_knowledge_invalid code => INVALID (
          "Attempting to reconstruct_into_c using an invalid attacker_knowledge" ++ code)
        | attacker_knowledge_empty => UNSUCCESSFUL
        | attacker_knowledge_c cm m next => match c with
            | value n => match get_equivalent_constant_attacker a c with
            | INVALID code => INVALID (
              "Found invalid constant in attacker" ++ code)
                | NOT_FOUND => match get_equivalent_constant_attacker a (SHAMIR_SPLIT1_c c), get_equivalent_constant_attacker a (SHAMIR_SPLIT2_c c), get_equivalent_constant_attacker a (SHAMIR_SPLIT3_c c) with
                    | INVALID code, _, _ => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | _, INVALID code, _ => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | _, _, INVALID code => INVALID (
                      "Found invalid constant in attacker" ++ code)    
                    | _, NOT_FOUND, NOT_FOUND => UNSUCCESSFUL 
                    | NOT_FOUND, _, NOT_FOUND => UNSUCCESSFUL 
                    | NOT_FOUND, NOT_FOUND, _ => UNSUCCESSFUL
                    | _, _, NOT_FOUND => let u := get_equivalent_constant_attacker a (SHAMIR_SPLIT1_c c) in let v := (SHAMIR_SPLIT2_c c) in let f := (get_equivalent_constant_attacker a) in SHAMIR_JOIN (f u) (f v)
                    | _, NOT_FOUND, _ => let u := get_equivalent_constant_attacker a (SHAMIR_SPLIT1_c c) in let v := (SHAMIR_SPLIT3_c c) in let f := (get_equivalent_constant_attacker a) in SHAMIR_JOIN (f u) (f v)
                    | NOT_FOUND, _, _ => let u := get_equivalent_constant_attacker a (SHAMIR_SPLIT2_c c) in let v := (SHAMIR_SPLIT3_c c) in let f := (get_equivalent_constant_attacker a) in SHAMIR_JOIN (f u) (f v)
                    | _, _, _ => c
                  end
                | _ => c
              end
            | pub_key_c _ exp => match reconstruct_into_c a exp with
                    | UNSUCCESSFUL => UNSUCCESSFUL
                    | _ => c
                  end
            | DH_c _ exp1 exp2 => match reconstruct_into_c a exp1, reconstruct_into_c a exp2 with
                | INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL => match reconstruct_into_c a (pub_key_c G exp2) with
                    | INVALID code => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | UNSUCCESSFUL => UNSUCCESSFUL
                    | _ => c
                  end
                | UNSUCCESSFUL, _ => match reconstruct_into_c a (pub_key_c G exp1) with
                    | INVALID code => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | UNSUCCESSFUL => UNSUCCESSFUL
                    | _ => c
                  end
                | _, _ => c
              end
            | HASH1_c c1 => match reconstruct_into_c a c1 with
                | INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL => UNSUCCESSFUL
                | _ => c
              end
            | HASH2_c c1 c2 => match reconstruct_into_c a c1, reconstruct_into_c a c2 with
                | INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL => let a1 := (learn_constant a c1) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _ => let a1 := (learn_constant a c2) in reconstruct_into_c a1 c
                | _, _ => c
              end
            | HASH3_c c1 c2 c3 => match reconstruct_into_c a c1, reconstruct_into_c a c2, reconstruct_into_c a c3 with
                | INVALID code, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := (learn_constant a c1) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL=> let a1 := (learn_constant a c2) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := (learn_constant a c3) in reconstruct_into_c a1 c
                | _, _, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c3 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, _, _ => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c3 in reconstruct_into_c a2 c
                | _, _, _ => c
              end
            | HASH4_c c1 c2 c3 c4 => match reconstruct_into_c a c1, reconstruct_into_c a c2, reconstruct_into_c a c3, reconstruct_into_c a c4  with
                | INVALID code, _, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := (learn_constant a c1) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := (learn_constant a c2) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := (learn_constant a c3) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := (learn_constant a c4) in reconstruct_into_c a1 c
                | _, _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c3 in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c4 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, _, _, UNSUCCESSFUL => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c3 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL, _ => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c4 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _, _ => let a1 := learn_constant a c3 in let a2 := learn_constant a1 c4 in reconstruct_into_c a2 c
                | _, _, _, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in let a3 := learn_constant a2 c3 in reconstruct_into_c a3 c
                | _, _, UNSUCCESSFUL, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in let a3 := learn_constant a2 c4 in reconstruct_into_c a3 c
                | _, UNSUCCESSFUL, _, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c3 in let a3 := learn_constant a2 c4 in reconstruct_into_c a3 c
                | UNSUCCESSFUL, _, _, _ => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c3 in let a3 := learn_constant a2 c4 in reconstruct_into_c a3 c
                | _, _, _, _ => c
              end 
            | HASH5_c c1 c2 c3 c4 c5 => match reconstruct_into_c a c1, reconstruct_into_c a c2, reconstruct_into_c a c3, reconstruct_into_c a c4, reconstruct_into_c a c5 with
                | INVALID code, _, _, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code, _, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, INVALID code, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, _, INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, _, _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := (learn_constant a c1) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := (learn_constant a c2) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := (learn_constant a c3) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := (learn_constant a c4) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := (learn_constant a c5) in reconstruct_into_c a1 c
                | _, _, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c3 in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c4 in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c5 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, _, _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c3 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c4 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c5 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _, _, UNSUCCESSFUL => let a1 := learn_constant a c3 in let a2 := learn_constant a1 c4 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _, UNSUCCESSFUL, _ => let a1 := learn_constant a c3 in let a2 := learn_constant a1 c5 in reconstruct_into_c a2 c
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, _, _ => let a1 := learn_constant a c4 in let a2 := learn_constant a1 c5 in reconstruct_into_c a2 c
                | _, _, _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in let a3 := learn_constant a2 c3 in reconstruct_into_c a3 c
                | _, _, UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in let a3 := learn_constant a2 c4 in reconstruct_into_c a3 c
                | _, _, UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in let a3 := learn_constant a2 c5 in reconstruct_into_c a3 c
                | _, UNSUCCESSFUL, _, _, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c3 in let a3 := learn_constant a2 c4 in reconstruct_into_c a3 c
                | _, UNSUCCESSFUL, _, UNSUCCESSFUL, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c3 in let a3 := learn_constant a2 c5 in reconstruct_into_c a3 c
                | _, UNSUCCESSFUL, UNSUCCESSFUL, _, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c4 in let a3 := learn_constant a2 c5 in reconstruct_into_c a3 c
                | UNSUCCESSFUL, _, _, UNSUCCESSFUL, _ => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c3 in let a3 := learn_constant a2 c5 in reconstruct_into_c a3 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL, _, _ => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c4 in let a3 := learn_constant a2 c5 in reconstruct_into_c a3 c
                | UNSUCCESSFUL, _, _, _, UNSUCCESSFUL => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c3 in let a3 := learn_constant a2 c5 in reconstruct_into_c a3 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _, _, _ => let a1 := learn_constant a c3 in let a2 := learn_constant a1 c4 in let a3 := learn_constant a2 c5 in reconstruct_into_c a3 c
                | _, _, _, _, UNSUCCESSFUL => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in let a3 := learn_constant a2 c3 in let a4 := learn_constant a3 c4 in reconstruct_into_c a4 c
                | _, _, _, UNSUCCESSFUL, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in let a3 := learn_constant a2 c3 in let a4 := learn_constant a3 c4 in reconstruct_into_c a4 c
                | _, _, UNSUCCESSFUL, _, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c2 in let a3 := learn_constant a2 c4 in let a4 := learn_constant a3 c5 in reconstruct_into_c a4 c
                | _, UNSUCCESSFUL, _, _, _ => let a1 := learn_constant a c1 in let a2 := learn_constant a1 c3 in let a3 := learn_constant a2 c4 in let a4 := learn_constant a3 c5 in reconstruct_into_c a4 c
                | UNSUCCESSFUL, _, _, _, _ => let a1 := learn_constant a c2 in let a2 := learn_constant a1 c3 in let a3 := learn_constant a2 c4 in let a4 := learn_constant a3 c5 in reconstruct_into_c a4 c
                | _, _, _, _, _ => c
              end
            | MAC_c key message => match reconstruct_into_c a key, reconstruct_into_c a message with
                | INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | UNSUCCESSFUL, _ => reconstruct_into_c (learn_constant a message) c
                | _, UNSUCCESSFUL => reconstruct_into_c (learn_constant a key) c
                | _, _ => c
              end
            | HKDF1_c salt ikm info => match reconstruct_into_c a salt, reconstruct_into_c a ikm, reconstruct_into_c a info with
                | INVALID code, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL, UNSUCCESSFUL => reconstruct_into_c (learn_constant a salt) c
                | UNSUCCESSFUL, _, UNSUCCESSFUL=> reconstruct_into_c (learn_constant a ikm) c
                | UNSUCCESSFUL, UNSUCCESSFUL, _ => reconstruct_into_c (learn_constant a info) c
                | UNSUCCESSFUL, _, _ => reconstruct_into_c (learn_constant (learn_constant a ikm) info) c
                | _, UNSUCCESSFUL, _ => reconstruct_into_c (learn_constant (learn_constant a salt) info) c
                | _, _, UNSUCCESSFUL => reconstruct_into_c (learn_constant (learn_constant a salt) ikm) c 
                | _, _, _ => c
              end
            | HKDF2_c salt ikm info => match reconstruct_into_c a salt, reconstruct_into_c a ikm, reconstruct_into_c a info with
                | INVALID code, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a salt in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := learn_constant a ikm in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := learn_constant a info in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, _  => let a1 := learn_constant a ikm in let a2 := learn_constant a1 info in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, _ => let a1 := learn_constant a salt in let a2 := learn_constant a1 info in reconstruct_into_c a2 c
                | _, _, UNSUCCESSFUL => let a1 := learn_constant a salt in let a2 := learn_constant a1 ikm in reconstruct_into_c a2 c
                | _, _, _ => c
              end
            | HKDF3_c salt ikm info => match reconstruct_into_c a salt, reconstruct_into_c a ikm, reconstruct_into_c a info with
                | INVALID code, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a salt in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := learn_constant a ikm in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := learn_constant a info in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, _  => let a1 := learn_constant a ikm in let a2 := learn_constant a1 info in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, _ => let a1 := learn_constant a salt in let a2 := learn_constant a1 info in reconstruct_into_c a2 c
                | _, _, UNSUCCESSFUL => let a1 := learn_constant a salt in let a2 := learn_constant a1 ikm in reconstruct_into_c a2 c
                | _, _, _ => c
              end
            | HKDF4_c salt ikm info => match reconstruct_into_c a salt, reconstruct_into_c a ikm, reconstruct_into_c a info with
                | INVALID code, _, _ => INVALID (
                 "Found invalid constant in attacker" ++ code)
                | _, INVALID code, _ => INVALID (
                 "Found invalid constant in attacker" ++ code)
                | _, _, INVALID code => INVALID (
                 "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a salt in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := learn_constant a ikm in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := learn_constant a info in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, _  => let a1 := learn_constant a ikm in let a2 := learn_constant a1 info in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, _ => let a1 := learn_constant a salt in let a2 := learn_constant a1 info in reconstruct_into_c a2 c
                | _, _, UNSUCCESSFUL => let a1 := learn_constant a salt in let a2 := learn_constant a1 ikm in reconstruct_into_c a2 c
               | _, _, _ => c
             end
            | HKDF5_c salt ikm info => match reconstruct_into_c a salt, reconstruct_into_c a ikm, reconstruct_into_c a info with
               | INVALID code, _, _ => INVALID (
                 "Found invalid constant in attacker" ++ code)
               | _, INVALID code, _ => INVALID (
                 "Found invalid constant in attacker" ++ code)
               | _, _, INVALID code => INVALID (
                 "Found invalid constant in attacker" ++ code)
               | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
               | _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a salt in reconstruct_into_c a1 c
               | UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := learn_constant a ikm in reconstruct_into_c a1 c
               | UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := learn_constant a info in reconstruct_into_c a1 c
               | UNSUCCESSFUL, _, _  => let a1 := learn_constant a ikm in let a2 := learn_constant a1 info in reconstruct_into_c a2 c
               | _, UNSUCCESSFUL, _ => let a1 := learn_constant a salt in let a2 := learn_constant a1 info in reconstruct_into_c a2 c
               | _, _, UNSUCCESSFUL => let a1 := learn_constant a salt in let a2 := learn_constant a1 ikm in reconstruct_into_c a2 c
               | _, _, _ => c
             end
            | PW_HASH_c x => match reconstruct_into_c a x with
                | INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL => UNSUCCESSFUL
                | _ => c
              end
            | SIGN_c k m => match reconstruct_into_c a k, reconstruct_into_c a m with
                | INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL => let a1 := learn_constant a k in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _ => let a1 := learn_constant a m in reconstruct_into_c a1 c
                | _, _ => c
              end
            | RINGSIGN_c ka gkb gkc m => match reconstruct_into_c a ka, reconstruct_into_c a gkb, reconstruct_into_c a gkc, reconstruct_into_c a m with
              | INVALID code, _, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code, _, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, _, _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                | _, UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := (learn_constant a ka) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := (learn_constant a gkb) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := (learn_constant a gkc) in reconstruct_into_c a1 c
                | UNSUCCESSFUL, UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := (learn_constant a m) in reconstruct_into_c a1 c
                | _, _, UNSUCCESSFUL, UNSUCCESSFUL => let a1 := learn_constant a ka in let a2 := learn_constant a1 gkb in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, _, UNSUCCESSFUL => let a1 := learn_constant a ka in let a2 := learn_constant a1 gkc in reconstruct_into_c a2 c
                | _, UNSUCCESSFUL, UNSUCCESSFUL, _ => let a1 := learn_constant a ka in let a2 := learn_constant a1 m in reconstruct_into_c a2 c
                | UNSUCCESSFUL, _, _, UNSUCCESSFUL => let a1 := learn_constant a gkb in let a2 := learn_constant a1 gkc in reconstruct_into_c a2 c
                | UNSUCCESSFUL, _, UNSUCCESSFUL, _ => let a1 := learn_constant a gkb in let a2 := learn_constant a1 m in reconstruct_into_c a2 c
                | UNSUCCESSFUL, UNSUCCESSFUL, _, _ => let a1 := learn_constant a gkc in let a2 := learn_constant a1 m in reconstruct_into_c a2 c
                | _, _, _, UNSUCCESSFUL => let a1 := learn_constant a ka in let a2 := learn_constant a1 gkb in let a3 := learn_constant a2 gkc in reconstruct_into_c a3 c
                | _, _, UNSUCCESSFUL, _ => let a1 := learn_constant a ka in let a2 := learn_constant a1 gkb in let a3 := learn_constant a2 m in reconstruct_into_c a3 c
                | _, UNSUCCESSFUL, _, _ => let a1 := learn_constant a ka in let a2 := learn_constant a1 gkc in let a3 := learn_constant a2 m in reconstruct_into_c a3 c
                | UNSUCCESSFUL, _, _, _ => let a1 := learn_constant a gkb in let a2 := learn_constant a1 gkc in let a3 := learn_constant a2 m in reconstruct_into_c a3 c
                | _, _, _, _ => c
              end
            | SHAMIR_SPLIT1_c k => match reconstruct_into_c a k with
                | INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL => match reconstruct_into_c a (SHAMIR_SPLIT2_c k), reconstruct_into_c a (SHAMIR_SPLIT3_c k) with
                    | INVALID code, _ => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | _, INVALID code => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                    | _, UNSUCCESSFUL => c
                    | UNSUCCESSFUL, _ => c
                    | _, _ => c
                  end
              end
            | SHAMIR_SPLIT2_c k => match reconstruct_into_c a k with
                | INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL => match reconstruct_into_c a (SHAMIR_SPLIT1_c k), reconstruct_into_c a (SHAMIR_SPLIT3_c k) with
                    | INVALID code, _ => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | _, INVALID code => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                    | _, UNSUCCESSFUL => c
                    | UNSUCCESSFUL, _ => c
                    | _, _ => c
                  end
              end
            | SHAMIR_SPLIT3_c k => match reconstruct_into_c a k with
                | INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | UNSUCCESSFUL => match reconstruct_into_c a (SHAMIR_SPLIT1_c k), reconstruct_into_c a (SHAMIR_SPLIT2_c k) with
                    | INVALID code, _ => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | _, INVALID code => INVALID (
                      "Found invalid constant in attacker" ++ code)
                    | UNSUCCESSFUL, UNSUCCESSFUL => UNSUCCESSFUL
                    | _, UNSUCCESSFUL => c
                    | UNSUCCESSFUL, _ => c
                    | _, _ => c
                  end
              end
            (* | SHAMIR_JOIN_c sa sb => match sa, sb with
                | INVALID code, _ => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | _, INVALID code => INVALID (
                  "Found invalid constant in attacker" ++ code)
                | SHAMIR_SPLIT1_c ka, SHAMIR_SPLIT2_c kb => match reconstruct_into_c a ka, reconstruct_into_c a kb with
                    |
                    |
                  end
                | SHAMIR_SPLIT1_c ka, SHAMIR_SPLIT3_c kb => match reconstruct_into_c a ka, reconstruct_into_c a kb with
                    |
                    |
                  end
                | SHAMIR_SPLIT2_c ka, SHAMIR_SPLIT3_c kb => match reconstruct_into_c a ka, reconstruct_into_c a kb with
                    |
                    |
                  end
              end *)
              | _ => c
            end end end.

                
              

      (* Fixpoint deduce_passive (ak: attacker_knowledge) : attacker_knowledge :=
      match ak with
      | attacker_knowledge_invalid code => attacker_knowledge_invalid (
        "Provided invalide attacker_knowledge to deduce_passive" ++ code) 
        | attacker_knowledge_c cm m next => match 
        
         *)
        (* Fixpoint deduce (a: attacker) : attacker :=
        match a with
        | attacker_invalid code => attacker_invalid (
          "Attempting to deduce using an invalid attacker; " ++ code)
          | attacker_c type lc ak => match type with
          | passive => attacker_constructor type lc (deduce_passive ak)
          | active => attacker_constructor type lc (deduce_active ak)
          end
          end.
           *)
         

(* Fixpoint query_confidentiality (a: attacker) (knowledgemap: k) (name: string) : string :=
  match getconstan k with
  match search_by_name_attacker a name with
    | false => "confidentiality ? " ++ name ++ ": PASS"
    | true => "confidentiality ? " ++ name ++ ": FAIL"
  end. *)

Fixpoint query_confidentiality (a: attacker) (name: string) : string :=
  match search_by_name_attacker a name with
    | false => "confidentiality ? " ++ name ++ ": PASS"
    | true => "confidentiality ? " ++ name ++ ": FAIL"
  end.

(*!DELIMITER!*)

(* Protocol: signal.vp *)

(* Phase 0: *)

Definition kmap_0 := knowledgemap_constructor "Alice".
Definition kmap_1 := add_principal_knowledgemap kmap_0 "Alice".
Definition kmap_2 := add_principal_knowledgemap kmap_1 "Bob".
Definition principal_alice_0 := get_principal_knowledgemap kmap_2 "Alice".
Definition principal_alice_1 := know_value principal_alice_0 "c0" public.
Definition principal_alice_2 := know_value principal_alice_1 "c1" public.
Definition principal_alice_3 := know_value principal_alice_2 "c2" public.
Definition principal_alice_4 := know_value principal_alice_3 "c3" public.
Definition principal_alice_5 := know_value principal_alice_4 "c4" public.
Definition principal_alice_6 := know_value principal_alice_5 "alongterm" private.
Definition principal_alice_7 := assign_value principal_alice_6 (public_key (get principal_alice_6 "alongterm")) "galongterm".
Definition kmap_3 := update_principal_knowledgemap kmap_2 principal_alice_7.
Definition attacker_1 := absorb_knowledgemap_attacker attacker_0 kmap_3.
Definition principal_bob_0 := get_principal_knowledgemap kmap_3 "Bob".
Definition principal_bob_1 := know_value principal_bob_0 "c0" public.
Definition principal_bob_2 := know_value principal_bob_1 "c1" public.
Definition principal_bob_3 := know_value principal_bob_2 "c2" public.
Definition principal_bob_4 := know_value principal_bob_3 "c3" public.
Definition principal_bob_5 := know_value principal_bob_4 "c4" public.
Definition principal_bob_6 := know_value principal_bob_5 "blongterm" private.
Definition principal_bob_7 := know_value principal_bob_6 "bs" private.
Definition principal_bob_8 := generate_value principal_bob_7 "bo".
Definition principal_bob_9 := assign_value principal_bob_8 (public_key (get principal_bob_8 "blongterm")) "gblongterm".
Definition principal_bob_10 := assign_value principal_bob_9 (public_key (get principal_bob_9 "bs")) "gbs".
Definition principal_bob_11 := assign_value principal_bob_10 (public_key (get principal_bob_10 "bo")) "gbo".
Definition principal_bob_12 := assign_value principal_bob_11 (SIGN (get principal_bob_11 "blongterm") (get principal_bob_11 "gbs")) "gbssig".
Definition kmap_4 := update_principal_knowledgemap kmap_3 principal_bob_12.
Definition attacker_2 := absorb_knowledgemap_attacker attacker_1 kmap_4.
Definition kmap_5 := add_message_knowledgemap kmap_4 (message_constructor "Bob" "Alice" "gblongterm" guarded).
Definition attacker_3 := absorb_knowledgemap_attacker attacker_2 kmap_5.
Definition kmap_6 := send_message kmap_5.
Definition kmap_7 := add_message_knowledgemap kmap_6 (message_constructor "Bob" "Alice" "gbssig" unguarded).
Definition attacker_4 := absorb_knowledgemap_attacker attacker_3 kmap_7.
Definition kmap_8 := send_message kmap_7.
Definition kmap_9 := add_message_knowledgemap kmap_8 (message_constructor "Bob" "Alice" "gbs" unguarded).
Definition attacker_5 := absorb_knowledgemap_attacker attacker_4 kmap_9.
Definition kmap_10 := send_message kmap_9.
Definition kmap_11 := add_message_knowledgemap kmap_10 (message_constructor "Bob" "Alice" "gbo" unguarded).
Definition attacker_6 := absorb_knowledgemap_attacker attacker_5 kmap_11.
Definition kmap_12 := send_message kmap_11.
Definition principal_alice_8 := get_principal_knowledgemap kmap_12 "Alice".
Definition principal_alice_9 := generate_value principal_alice_8 "ae1".
Definition principal_alice_10 := assign_value principal_alice_9 (public_key (get principal_alice_9 "ae1")) "gae1".
Definition principal_alice_11 := assign_value principal_alice_10 (DH (get principal_alice_10 "gbs")(get principal_alice_10 "alongterm")) "unnamed_0".
Definition principal_alice_12 := assign_value principal_alice_11 (DH (get principal_alice_11 "gblongterm")(get principal_alice_11 "ae1")) "unnamed_1".
Definition principal_alice_13 := assign_value principal_alice_12 (DH (get principal_alice_12 "gbs")(get principal_alice_12 "ae1")) "unnamed_2".
Definition principal_alice_14 := assign_value principal_alice_13 (DH (get principal_alice_13 "gbo")(get principal_alice_13 "ae1")) "unnamed_3".
Definition principal_alice_15 := assign_value principal_alice_14 (HASH5 (get principal_alice_10 "c0") (get principal_alice_11 "unnamed_0") (get principal_alice_12 "unnamed_1") (get principal_alice_13 "unnamed_2") (get principal_alice_14 "unnamed_3")) "amaster".
Definition principal_alice_16 := assign_value principal_alice_15 (HKDF1 (get principal_alice_15 "amaster") (get principal_alice_15 "c1") (get principal_alice_15 "c2")) "arkba1".
Definition principal_alice_17 := assign_value principal_alice_16 (HKDF2 (get principal_alice_16 "amaster") (get principal_alice_16 "c1") (get principal_alice_16 "c2")) "ackba1".
Definition kmap_13 := update_principal_knowledgemap kmap_12 principal_alice_17.
Definition attacker_7 := absorb_knowledgemap_attacker attacker_6 kmap_13.
Definition principal_alice_18 := get_principal_knowledgemap kmap_13 "Alice".
Definition principal_alice_19 := generate_value principal_alice_18 "m1".
Definition principal_alice_20 := generate_value principal_alice_19 "ae2".
Definition principal_alice_21 := assign_value principal_alice_20 (public_key (get principal_alice_20 "ae2")) "gae2".
Definition principal_alice_22 := assign_value principal_alice_21 (SIGNVERIF (get principal_alice_21 "gblongterm") (get principal_alice_21 "gbs") (get principal_alice_21 "gbssig")) "unnamed_0".
Definition principal_alice_23 := assign_value principal_alice_22 (DH (get principal_alice_22 "gbs")(get principal_alice_22 "ae2")) "akshared1".
Definition principal_alice_24 := assign_value principal_alice_23 (HKDF1 (get principal_alice_23 "akshared1") (get principal_alice_23 "arkba1") (get principal_alice_23 "c2")) "arkab1".
Definition principal_alice_25 := assign_value principal_alice_24 (HKDF2 (get principal_alice_24 "akshared1") (get principal_alice_24 "arkba1") (get principal_alice_24 "c2")) "ackab1".
Definition principal_alice_26 := assign_value principal_alice_25 (MAC (get principal_alice_25 "ackab1") (get principal_alice_25 "c3")) "unnamed_4".
Definition principal_alice_27 := assign_value principal_alice_26 (HKDF1 (get principal_alice_26 "unnamed_4") (get principal_alice_26 "c1") (get principal_alice_26 "c4")) "akenc1".
Definition principal_alice_28 := assign_value principal_alice_27 (MAC (get principal_alice_27 "ackab1") (get principal_alice_27 "c3")) "unnamed_5".
Definition principal_alice_29 := assign_value principal_alice_28 (HKDF2 (get principal_alice_28 "unnamed_5") (get principal_alice_28 "c1") (get principal_alice_28 "c4")) "akenc2".
Definition principal_alice_30 := assign_value principal_alice_29 (HASH3 (get principal_alice_29 "galongterm") (get principal_alice_29 "gblongterm") (get principal_alice_29 "gae2")) "unnamed_6".
Definition principal_alice_31 := assign_value principal_alice_30 (AEAD_ENC (get principal_alice_29 "akenc1") (get principal_alice_29 "m1") (get principal_alice_30 "unnamed_6")) "e1".
Definition kmap_14 := update_principal_knowledgemap kmap_13 principal_alice_31.
Definition attacker_8 := absorb_knowledgemap_attacker attacker_7 kmap_14.
Definition kmap_15 := add_message_knowledgemap kmap_14 (message_constructor "Alice" "Bob" "galongterm" guarded).
Definition attacker_9 := absorb_knowledgemap_attacker attacker_8 kmap_15.
Definition kmap_16 := send_message kmap_15.
Definition kmap_17 := add_message_knowledgemap kmap_16 (message_constructor "Alice" "Bob" "gae1" unguarded).
Definition attacker_10 := absorb_knowledgemap_attacker attacker_9 kmap_17.
Definition kmap_18 := send_message kmap_17.
Definition kmap_19 := add_message_knowledgemap kmap_18 (message_constructor "Alice" "Bob" "gae2" unguarded).
Definition attacker_11 := absorb_knowledgemap_attacker attacker_10 kmap_19.
Definition kmap_20 := send_message kmap_19.
Definition kmap_21 := add_message_knowledgemap kmap_20 (message_constructor "Alice" "Bob" "e1" unguarded).
Definition attacker_12 := absorb_knowledgemap_attacker attacker_11 kmap_21.
Definition kmap_22 := send_message kmap_21.
Definition principal_bob_13 := get_principal_knowledgemap kmap_22 "Bob".
Definition principal_bob_14 := assign_value principal_bob_13 (DH (get principal_bob_13 "galongterm")(get principal_bob_13 "bs")) "unnamed_7".
Definition principal_bob_15 := assign_value principal_bob_14 (DH (get principal_bob_14 "gae1")(get principal_bob_14 "blongterm")) "unnamed_8".
Definition principal_bob_16 := assign_value principal_bob_15 (DH (get principal_bob_15 "gae1")(get principal_bob_15 "bs")) "unnamed_9".
Definition principal_bob_17 := assign_value principal_bob_16 (DH (get principal_bob_16 "gae1")(get principal_bob_16 "bo")) "unnamed_10".
Definition principal_bob_18 := assign_value principal_bob_17 (HASH5 (get principal_bob_13 "c0") (get principal_bob_14 "unnamed_7") (get principal_bob_15 "unnamed_8") (get principal_bob_16 "unnamed_9") (get principal_bob_17 "unnamed_10")) "bmaster".
Definition principal_bob_19 := assign_value principal_bob_18 (HKDF1 (get principal_bob_18 "bmaster") (get principal_bob_18 "c1") (get principal_bob_18 "c2")) "brkba1".
Definition principal_bob_20 := assign_value principal_bob_19 (HKDF2 (get principal_bob_19 "bmaster") (get principal_bob_19 "c1") (get principal_bob_19 "c2")) "bckba1".
Definition kmap_23 := update_principal_knowledgemap kmap_22 principal_bob_20.
Definition attacker_13 := absorb_knowledgemap_attacker attacker_12 kmap_23.
Definition principal_bob_21 := get_principal_knowledgemap kmap_23 "Bob".
Definition principal_bob_22 := assign_value principal_bob_21 (DH (get principal_bob_21 "gae2")(get principal_bob_21 "bs")) "bkshared1".
Definition principal_bob_23 := assign_value principal_bob_22 (HKDF1 (get principal_bob_22 "bkshared1") (get principal_bob_22 "brkba1") (get principal_bob_22 "c2")) "brkab1".
Definition principal_bob_24 := assign_value principal_bob_23 (HKDF2 (get principal_bob_23 "bkshared1") (get principal_bob_23 "brkba1") (get principal_bob_23 "c2")) "bckab1".
Definition principal_bob_25 := assign_value principal_bob_24 (MAC (get principal_bob_24 "bckab1") (get principal_bob_24 "c3")) "unnamed_11".
Definition principal_bob_26 := assign_value principal_bob_25 (HKDF1 (get principal_bob_25 "unnamed_11") (get principal_bob_25 "c1") (get principal_bob_25 "c4")) "bkenc1".
Definition principal_bob_27 := assign_value principal_bob_26 (MAC (get principal_bob_26 "bckab1") (get principal_bob_26 "c3")) "unnamed_12".
Definition principal_bob_28 := assign_value principal_bob_27 (HKDF2 (get principal_bob_27 "unnamed_12") (get principal_bob_27 "c1") (get principal_bob_27 "c4")) "bkenc2".
Definition principal_bob_29 := assign_value principal_bob_28 (HASH3 (get principal_bob_28 "galongterm") (get principal_bob_28 "gblongterm") (get principal_bob_28 "gae2")) "unnamed_13".
Definition principal_bob_30 := assign_value principal_bob_29 (AEAD_DEC (get principal_bob_28 "bkenc1") (get principal_bob_28 "e1") (get principal_bob_29 "unnamed_13")) "m1_d".
Definition kmap_24 := update_principal_knowledgemap kmap_23 principal_bob_30.
Definition attacker_14 := absorb_knowledgemap_attacker attacker_13 kmap_24.
Definition principal_bob_31 := get_principal_knowledgemap kmap_24 "Bob".
Definition principal_bob_32 := generate_value principal_bob_31 "m2".
Definition principal_bob_33 := generate_value principal_bob_32 "be".
Definition principal_bob_34 := assign_value principal_bob_33 (public_key (get principal_bob_33 "be")) "gbe".
Definition principal_bob_35 := assign_value principal_bob_34 (DH (get principal_bob_34 "gae2")(get principal_bob_34 "be")) "bkshared2".
Definition principal_bob_36 := assign_value principal_bob_35 (HKDF1 (get principal_bob_35 "bkshared2") (get principal_bob_35 "brkab1") (get principal_bob_35 "c2")) "brkba2".
Definition principal_bob_37 := assign_value principal_bob_36 (HKDF2 (get principal_bob_36 "bkshared2") (get principal_bob_36 "brkab1") (get principal_bob_36 "c2")) "bckba2".
Definition principal_bob_38 := assign_value principal_bob_37 (MAC (get principal_bob_37 "bckba2") (get principal_bob_37 "c3")) "unnamed_14".
Definition principal_bob_39 := assign_value principal_bob_38 (HKDF1 (get principal_bob_38 "unnamed_14") (get principal_bob_38 "c1") (get principal_bob_38 "c4")) "bkenc3".
Definition principal_bob_40 := assign_value principal_bob_39 (MAC (get principal_bob_39 "bckba2") (get principal_bob_39 "c3")) "unnamed_15".
Definition principal_bob_41 := assign_value principal_bob_40 (HKDF2 (get principal_bob_40 "unnamed_15") (get principal_bob_40 "c1") (get principal_bob_40 "c4")) "bkenc4".
Definition principal_bob_42 := assign_value principal_bob_41 (HASH3 (get principal_bob_41 "gblongterm") (get principal_bob_41 "galongterm") (get principal_bob_41 "gbe")) "unnamed_16".
Definition principal_bob_43 := assign_value principal_bob_42 (AEAD_ENC (get principal_bob_41 "bkenc3") (get principal_bob_41 "m2") (get principal_bob_42 "unnamed_16")) "e2".
Definition kmap_25 := update_principal_knowledgemap kmap_24 principal_bob_43.
Definition attacker_15 := absorb_knowledgemap_attacker attacker_14 kmap_25.
Definition kmap_26 := add_message_knowledgemap kmap_25 (message_constructor "Bob" "Alice" "gbe" unguarded).
Definition attacker_16 := absorb_knowledgemap_attacker attacker_15 kmap_26.
Definition kmap_27 := send_message kmap_26.
Definition kmap_28 := add_message_knowledgemap kmap_27 (message_constructor "Bob" "Alice" "e2" unguarded).
Definition attacker_17 := absorb_knowledgemap_attacker attacker_16 kmap_28.
Definition kmap_29 := send_message kmap_28.
Definition principal_alice_32 := get_principal_knowledgemap kmap_29 "Alice".
Definition principal_alice_33 := assign_value principal_alice_32 (DH (get principal_alice_32 "gbe")(get principal_alice_32 "ae2")) "akshared2".
Definition principal_alice_34 := assign_value principal_alice_33 (HKDF1 (get principal_alice_33 "akshared2") (get principal_alice_33 "arkab1") (get principal_alice_33 "c2")) "arkba2".
Definition principal_alice_35 := assign_value principal_alice_34 (HKDF2 (get principal_alice_34 "akshared2") (get principal_alice_34 "arkab1") (get principal_alice_34 "c2")) "ackba2".
Definition principal_alice_36 := assign_value principal_alice_35 (MAC (get principal_alice_35 "ackba2") (get principal_alice_35 "c3")) "unnamed_17".
Definition principal_alice_37 := assign_value principal_alice_36 (HKDF1 (get principal_alice_36 "unnamed_17") (get principal_alice_36 "c1") (get principal_alice_36 "c4")) "akenc3".
Definition principal_alice_38 := assign_value principal_alice_37 (MAC (get principal_alice_37 "ackba2") (get principal_alice_37 "c3")) "unnamed_18".
Definition principal_alice_39 := assign_value principal_alice_38 (HKDF2 (get principal_alice_38 "unnamed_18") (get principal_alice_38 "c1") (get principal_alice_38 "c4")) "akenc4".
Definition principal_alice_40 := assign_value principal_alice_39 (HASH3 (get principal_alice_39 "gblongterm") (get principal_alice_39 "galongterm") (get principal_alice_39 "gbe")) "unnamed_19".
Definition principal_alice_41 := assign_value principal_alice_40 (AEAD_DEC (get principal_alice_39 "akenc3") (get principal_alice_39 "e2") (get principal_alice_40 "unnamed_19")) "m2_d".
Definition kmap_30 := update_principal_knowledgemap kmap_29 principal_alice_41.
Definition attacker_18 := absorb_knowledgemap_attacker attacker_17 kmap_30.
Definition principal_alice_42 := get_principal_knowledgemap kmap_30 "Alice".
Definition principal_alice_43 := generate_value principal_alice_42 "m3".
Definition principal_alice_44 := generate_value principal_alice_43 "ae3".
Definition principal_alice_45 := assign_value principal_alice_44 (public_key (get principal_alice_44 "ae3")) "gae3".
Definition principal_alice_46 := assign_value principal_alice_45 (DH (get principal_alice_45 "gbe")(get principal_alice_45 "ae3")) "akshared3".
Definition principal_alice_47 := assign_value principal_alice_46 (HKDF1 (get principal_alice_46 "akshared3") (get principal_alice_46 "arkba2") (get principal_alice_46 "c2")) "arkab3".
Definition principal_alice_48 := assign_value principal_alice_47 (HKDF2 (get principal_alice_47 "akshared3") (get principal_alice_47 "arkba2") (get principal_alice_47 "c2")) "ackab3".
Definition principal_alice_49 := assign_value principal_alice_48 (MAC (get principal_alice_48 "ackab3") (get principal_alice_48 "c3")) "unnamed_20".
Definition principal_alice_50 := assign_value principal_alice_49 (HKDF1 (get principal_alice_49 "unnamed_20") (get principal_alice_49 "c1") (get principal_alice_49 "c4")) "akenc5".
Definition principal_alice_51 := assign_value principal_alice_50 (MAC (get principal_alice_50 "ackab3") (get principal_alice_50 "c3")) "unnamed_21".
Definition principal_alice_52 := assign_value principal_alice_51 (HKDF2 (get principal_alice_51 "unnamed_21") (get principal_alice_51 "c1") (get principal_alice_51 "c4")) "akenc6".
Definition principal_alice_53 := assign_value principal_alice_52 (HASH3 (get principal_alice_52 "gblongterm") (get principal_alice_52 "galongterm") (get principal_alice_52 "gae3")) "unnamed_22".
Definition principal_alice_54 := assign_value principal_alice_53 (AEAD_ENC (get principal_alice_52 "akenc5") (get principal_alice_52 "m3") (get principal_alice_53 "unnamed_22")) "e3".
Definition kmap_31 := update_principal_knowledgemap kmap_30 principal_alice_54.
Definition attacker_19 := absorb_knowledgemap_attacker attacker_18 kmap_31.
Definition kmap_32 := add_message_knowledgemap kmap_31 (message_constructor "Alice" "Bob" "gae3" unguarded).
Definition attacker_20 := absorb_knowledgemap_attacker attacker_19 kmap_32.
Definition kmap_33 := send_message kmap_32.
Definition kmap_34 := add_message_knowledgemap kmap_33 (message_constructor "Alice" "Bob" "e3" unguarded).
Definition attacker_21 := absorb_knowledgemap_attacker attacker_20 kmap_34.
Definition kmap_35 := send_message kmap_34.
Definition principal_bob_44 := get_principal_knowledgemap kmap_35 "Bob".
Definition principal_bob_45 := assign_value principal_bob_44 (DH (get principal_bob_44 "gae3")(get principal_bob_44 "be")) "bkshared3".
Definition principal_bob_46 := assign_value principal_bob_45 (HKDF1 (get principal_bob_45 "bkshared3") (get principal_bob_45 "brkba2") (get principal_bob_45 "c2")) "brkab3".
Definition principal_bob_47 := assign_value principal_bob_46 (HKDF2 (get principal_bob_46 "bkshared3") (get principal_bob_46 "brkba2") (get principal_bob_46 "c2")) "bckab3".
Definition principal_bob_48 := assign_value principal_bob_47 (MAC (get principal_bob_47 "bckab3") (get principal_bob_47 "c3")) "unnamed_23".
Definition principal_bob_49 := assign_value principal_bob_48 (HKDF1 (get principal_bob_48 "unnamed_23") (get principal_bob_48 "c1") (get principal_bob_48 "c4")) "bkenc5".
Definition principal_bob_50 := assign_value principal_bob_49 (MAC (get principal_bob_49 "bckab3") (get principal_bob_49 "c3")) "unnamed_24".
Definition principal_bob_51 := assign_value principal_bob_50 (HKDF2 (get principal_bob_50 "unnamed_24") (get principal_bob_50 "c1") (get principal_bob_50 "c4")) "bkenc6".
Definition principal_bob_52 := assign_value principal_bob_51 (HASH3 (get principal_bob_51 "gblongterm") (get principal_bob_51 "galongterm") (get principal_bob_51 "gae3")) "unnamed_25".
Definition principal_bob_53 := assign_value principal_bob_52 (AEAD_DEC (get principal_bob_51 "bkenc5") (get principal_bob_51 "e3") (get principal_bob_52 "unnamed_25")) "m3_d".
Definition kmap_36 := update_principal_knowledgemap kmap_35 principal_bob_53.
Definition attacker_22 := absorb_knowledgemap_attacker attacker_21 kmap_36.

(* Phase 0 queries *)
Compute(query_confidentiality attacker_22 "m1").
(* Query not supported *)
Compute(query_confidentiality attacker_22 "m2").
(* Query not supported *)
Compute(query_confidentiality attacker_22 "m3").
(* Query not supported *)

(* Phase 1: *)

Definition principal_alice_55 := get_principal_knowledgemap kmap_36 "Alice".
Definition principal_alice_56 := leak_value principal_alice_55 "alongterm".
Definition kmap_37 := update_principal_knowledgemap kmap_36 principal_alice_56.
Definition attacker_23 := absorb_knowledgemap_attacker attacker_22 kmap_37.
Definition principal_bob_54 := get_principal_knowledgemap kmap_37 "Bob".
Definition principal_bob_55 := leak_value principal_bob_54 "blongterm".
Definition kmap_38 := update_principal_knowledgemap kmap_37 principal_bob_55.
Definition attacker_24 := absorb_knowledgemap_attacker attacker_23 kmap_38.

(* Phase 1 queries *)
Compute(query_confidentiality attacker_24 "m1").
(* Query not supported *)
Compute(query_confidentiality attacker_24 "m2").
(* Query not supported *)
Compute(query_confidentiality attacker_24 "m3").
(* Query not supported *)