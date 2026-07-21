#![no_std]
use soroban_sdk::{contract, contracttype, contractimpl, Address, Env, symbol_short};

// BREAKING CHANGE: field `amount` changed from `i128` to `u32`
#[contracttype]
pub struct Balance {
    pub amount: u32,
    pub owner: Address,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
}

#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    // BREAKING CHANGE: dropped require_auth() call
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let balance = Balance { amount: amount as u32, owner: to.clone() };
        env.storage().persistent().set(&DataKey::Balance(to), &balance);
    }

    pub fn admin_op(env: Env, admin: Address) {
        admin.require_auth_for_args((&admin,));
    }

    pub fn balance(env: Env, addr: Address) -> i128 {
        env.storage()
            .persistent()
            .get::<_, Balance>(&DataKey::Balance(addr))
            .map(|b| b.amount as i128)
            .unwrap_or(0)
    }
}
