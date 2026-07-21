#![no_std]
use soroban_sdk::{contract, contracttype, contractimpl, Address, Env, symbol_short};

#[contracttype]
pub struct Balance {
    pub amount: i128,
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

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let balance = Balance { amount, owner: to.clone() };
        env.storage().persistent().set(&DataKey::Balance(to), &balance);
    }

    pub fn admin_op(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn balance(env: Env, addr: Address) -> i128 {
        env.storage()
            .persistent()
            .get::<_, Balance>(&DataKey::Balance(addr))
            .map(|b| b.amount)
            .unwrap_or(0)
    }
}
