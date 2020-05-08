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