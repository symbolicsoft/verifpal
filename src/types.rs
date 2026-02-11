/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

pub type PrincipalId = u8;
pub type ValueId = u32;
pub type PrimitiveId = u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypesEnum {
    Empty,
    Private,
    Public,
    Password,
    Knows,
    Generates,
    Assignment,
    Leaks,
    Confidentiality,
    Authentication,
    Freshness,
    Unlinkability,
    Equivalence,
    Precondition,
}

#[derive(Clone, Debug)]
pub enum Value {
    Constant(Constant),
    Primitive(Arc<Primitive>),
    Equation(Arc<Equation>),
}

impl Value {
    pub fn as_constant(&self) -> Option<&Constant> {
        match self {
            Value::Constant(c) => Some(c),
            _ => None,
        }
    }

    pub fn as_primitive(&self) -> Option<&Primitive> {
        match self {
            Value::Primitive(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_equation(&self) -> Option<&Equation> {
        match self {
            Value::Equation(e) => Some(e),
            _ => None,
        }
    }

    pub fn as_primitive_mut(&mut self) -> Option<&mut Primitive> {
        match self {
            Value::Primitive(p) => Some(Arc::make_mut(p)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Constant {
    pub name: Arc<str>,
    pub id: ValueId,
    pub guard: bool,
    pub fresh: bool,
    pub leaked: bool,
    pub declaration: TypesEnum,
    pub qualifier: TypesEnum,
}

#[derive(Clone, Debug)]
pub struct Primitive {
    pub id: PrimitiveId,
    pub arguments: Vec<Value>,
    pub output: usize,
    pub check: bool,
}

#[derive(Clone, Debug)]
pub struct Equation {
    pub values: Vec<Value>,
}

#[derive(Clone, Debug)]
pub struct Model {
    pub file_name: String,
    pub attacker: String,
    pub blocks: Vec<Block>,
    pub queries: Vec<Query>,
}

#[derive(Clone, Debug)]
pub struct VerifyResult {
    pub query: Query,
    pub query_index: usize,
    pub resolved: bool,
    pub summary: String,
    pub options: Vec<QueryOptionResult>,
}

#[derive(Clone, Debug, Default)]
pub struct Block {
    pub kind: String,
    pub principal: Principal,
    pub message: Message,
    pub phase: Phase,
}

#[derive(Clone, Debug, Default)]
pub struct Principal {
    pub name: String,
    pub id: PrincipalId,
    pub expressions: Vec<Expression>,
}

#[derive(Clone, Debug, Default)]
pub struct Message {
    pub sender: PrincipalId,
    pub recipient: PrincipalId,
    pub constants: Vec<Constant>,
}

#[derive(Clone, Debug, Default)]
pub struct Phase {
    pub number: i32,
}

#[derive(Clone, Debug)]
pub struct Query {
    pub kind: TypesEnum,
    pub constants: Vec<Constant>,
    pub message: Message,
    pub options: Vec<QueryOption>,
}

#[derive(Clone, Debug)]
pub struct QueryOption {
    pub kind: TypesEnum,
    pub message: Message,
}

#[derive(Clone, Debug)]
pub struct QueryOptionResult {
    pub resolved: bool,
    pub summary: String,
}

#[derive(Clone, Debug)]
pub struct Expression {
    pub kind: TypesEnum,
    pub qualifier: TypesEnum,
    pub constants: Vec<Constant>,
    pub assigned: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct KnowledgeMap {
    pub principals: Vec<String>,
    pub principal_ids: Vec<PrincipalId>,
    pub constants: Vec<Constant>,
    pub assigned: Vec<Value>,
    pub creator: Vec<PrincipalId>,
    pub known_by: Vec<Vec<HashMap<PrincipalId, PrincipalId>>>,
    pub declared_at: Vec<i32>,
    pub max_declared_at: i32,
    pub phase: Vec<Vec<i32>>,
    pub max_phase: i32,
    pub constant_index: HashMap<ValueId, usize>,
    pub used_by: HashMap<ValueId, HashMap<PrincipalId, bool>>,
}

#[derive(Clone, Debug)]
pub struct PrincipalState {
    pub name: String,
    pub id: PrincipalId,
    // Shared/immutable fields (Arc for cheap cloning, matching Go's shallow copy)
    pub constants: Arc<Vec<Constant>>,
    pub guard: Arc<Vec<bool>>,
    pub known: Arc<Vec<bool>>,
    pub wire: Arc<Vec<Vec<PrincipalId>>>,
    pub known_by: Arc<Vec<Vec<HashMap<PrincipalId, PrincipalId>>>>,
    pub declared_at: Arc<Vec<i32>>,
    pub max_declared_at: i32,
    pub mutatable_to: Arc<Vec<Vec<PrincipalId>>>,
    pub phase: Arc<Vec<Vec<i32>>>,
    pub constant_index: Arc<HashMap<ValueId, usize>>,
    // Mutable fields (deep-cloned)
    pub assigned: Vec<Value>,
    pub creator: Vec<PrincipalId>,
    pub sender: Vec<PrincipalId>,
    pub rewritten: Vec<bool>,
    pub before_rewrite: Vec<Value>,
    pub mutated: Vec<bool>,
    pub before_mutate: Vec<Value>,
}

#[derive(Clone, Debug)]
pub struct AttackerState {
    pub current_phase: i32,
    pub exhausted: bool,
    pub known: Arc<Vec<Value>>,
    pub known_map: Arc<HashMap<u64, Vec<usize>>>,
    pub skeleton_hashes: Arc<HashSet<u64>>,
    pub principal_state: Arc<Vec<Arc<PrincipalState>>>,
}

#[derive(Clone, Debug)]
pub struct MutationMap {
    pub out_of_mutations: bool,
    pub constants: Vec<Constant>,
    pub mutations: Vec<Vec<Value>>,
    pub combination: Vec<Value>,
    pub depth_index: Vec<usize>,
}

