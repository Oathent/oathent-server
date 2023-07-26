import * as fs from "fs/promises";
import path from "path";

interface Scopes {
    [scope: string]: number;
}

function hasDuplicates(scopes: Scopes) {
    return (new Set(Object.keys(scopes))).size !== Object.keys(scopes).length
        && (new Set(Object.values(scopes))).size !== Object.values(scopes).length;
}

function hasNonPowers(scopes: Scopes) {
    return Object.values(scopes).reduce((p, c) => !p && !(c && !(c & c-1)), false);
}

function hasCustomOverwrittenDefaultScopes() {
    return Object.keys(SCOPES).length != (Object.keys(DEFAULT_SCOPES).length + Object.keys(CUSTOM_SCOPES).length);
}

const DEFAULT_SCOPES: Scopes = {
    'user:identify': 0,
    'user:email': 1,
    'user:apps': 2,
} as const

let CUSTOM_SCOPES: Scopes = {};

export let MAX_SCOPE: number;

export let SCOPES: Scopes = DEFAULT_SCOPES;

const CUSTOM_SCOPES_FILE = path.join(__dirname, '../../custom-scopes.json');
export async function initialiseScopes() {
    if(hasNonPowers(DEFAULT_SCOPES))
        throw new Error("Default scopes contained values that were not powers of 2! This should never happen!");

    if(hasDuplicates(DEFAULT_SCOPES))
        throw new Error("Default scopes contained duplicated values! This should never happen!");

    try {
        await fs.access(CUSTOM_SCOPES_FILE, fs.constants.R_OK)
        CUSTOM_SCOPES = JSON.parse(await fs.readFile(CUSTOM_SCOPES_FILE, 'utf-8'));
    } catch(e) {}

    if(hasNonPowers(CUSTOM_SCOPES))
        throw new Error("Custom scopes contained values that were not powers of 2! This should never happen!");

    if(hasDuplicates(CUSTOM_SCOPES))
        throw new Error("Custom scopes contained duplicated values! Please fix your configuration!");


    SCOPES = Object.assign({}, DEFAULT_SCOPES, CUSTOM_SCOPES);
    MAX_SCOPE = Object.values(SCOPES).reduce((p, c) => p + c, 0);

    if(hasDuplicates(SCOPES) || hasCustomOverwrittenDefaultScopes())
        throw new Error("Custom scopes overwrote 1 or more default scopes! Please fix your configuration!");

}

export function filterScopes(scopes: string[]) {
    if(!scopes)
        return [];

    return scopes.filter(s => Object.keys(SCOPES).includes(s));
}

export function scopeValToName(val: number) {
    return Object.keys(SCOPES).find(s => SCOPES[s] == val);
}