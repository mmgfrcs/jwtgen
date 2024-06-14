<script lang="ts">
  
  import {SignJWT} from 'jose'
  import { browser } from '$app/environment';
	import { slide } from 'svelte/transition';
	import { DatePicker } from "@svelte-plugins/datepicker";

  type ClaimProp = {
    idx: number, 
    disableName: boolean, 
    isPickerOpen: boolean, 
    
    name: string, 
    value: string
  }

  let alg = "HS256"
  let secret = ""
  let privKey = ""
  let claims: ClaimProp[] = []
  let token = ""

  let disableGenerate: boolean = true

  let tokenSpan: HTMLElement | undefined

  function canGenerate() {
    disableGenerate = !((alg.startsWith("HS") && secret != "") || (alg.startsWith("RS") && privKey != ""))
    return !disableGenerate
  }

  async function generateHS256() {
    const k = await crypto.subtle.generateKey({name: "HMAC", hash: "SHA-256"},true, ["sign", "verify"])
    secret = Buffer.from(new Uint8Array(await crypto.subtle.exportKey("raw", k))).toString("hex")
    canGenerate()
  }

  async function generateRS256() {
    const k = await crypto.subtle.generateKey({name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256", publicExponent: new Uint8Array([0x01, 0, 0x01])}, true, ["sign", "verify"])
    privKey = Buffer.from(await crypto.subtle.exportKey("pkcs8", k.privateKey)).toString("base64")
    canGenerate()
  }

  async function generateJWT() {
    if (!canGenerate()) return
    console.log("Click")
    const s = new TextEncoder().encode(secret)

    const payload = Object.assign({}, ...claims.map(x=>{return {[x.name]: ["iat","nbf","exp"].includes(x.name) ? Number(x.value) : x.value}}))

    token = await new SignJWT(payload)
      .setProtectedHeader({ alg, typ: "JWT" })
      .sign(s)

    if (tokenSpan !== undefined) tokenSpan.innerText = token
  }

  function onClaimTypeChange(e: Event & {currentTarget: HTMLSelectElement}, claim: ClaimProp) {
    const claimIdx = claims.indexOf(claim)
    const typ = e.currentTarget.value
    if (typ !== "Custom") {
      claims[claimIdx].name = typ
      claims[claimIdx].disableName = true
    } else {
      claims[claimIdx].name = ""
      claims[claimIdx].disableName = false
    }
  }
</script>

<h1 class="text-2xl pb-4">Generate JWT</h1>
<form class="w-full pb-4">
  <h2 class="text-xl">Signature</h2>
  <label class="form-control w-full">
    <div class="label">
      <span class="label-text">Algorithm</span>
    </div>
    <select class="select select-bordered w-full max-w-xs" bind:value={alg}>
      <option selected>HS256</option>
      <!-- <option>RS256</option> -->
    </select>
  </label>
  {#if alg == "HS256"}
    <label class="form-control w-full">
      <div class="label">
        <span class="label-text">HS256 Secret</span>
        {#if browser && window.isSecureContext}
          <span class="label-text-alt">
            <button class="btn btn-sm btn-primary" on:click={generateHS256}>Generate</button>
          </span>
        {/if}
      </div>
      <input type="text" placeholder="Type HMAC Secret here" class="input input-bordered w-full" bind:value={secret} on:input={canGenerate} />
    </label>
  {:else if alg == "RS256"}
    <label class="form-control w-full">
      <div class="label">
        <span class="label-text">RS256 Private Key</span>
        <span class="label-text-alt">
          <button class="btn btn-sm btn-primary" on:click={generateRS256}>Generate</button>
        </span>
      </div>
      <textarea class="textarea textarea-bordered h-24" bind:value={privKey}  on:input={canGenerate}></textarea>
    </label>
    <label class="form-control w-full">
      <div class="label">
        <span class="label-text">RS256 Public Key</span>
      </div>
      <textarea disabled class="textarea textarea-bordered h-24"></textarea>
    </label>
  {/if}
  <div class="divider"></div>
  <div class="flex flex-1 flex-row items-center justify-between pb-4">
    <h2 class="text-xl">Claims</h2>
    <button class="btn btn-sm btn-primary" on:click={(x)=>claims = [...claims, {idx: new Date().getTime(), disableName: false, isPickerOpen: false, name: "", value: ""}]}>Add</button>
  </div>
  
  {#each claims as claim (claim.idx)}
    <div class="join w-full pb-4" transition:slide>
      <select class="select select-bordered join-item" on:change={(e)=>onClaimTypeChange(e, claim)}>
        <option selected>Custom</option>
        <option value="iss">Issuer</option>
        <option value="iat">Issued At</option>
        <option value="exp">Expiration Time</option>
        <option value="nbf">Not Before Time</option>
        <option value="sub">Subject</option>
        <option value="aud">Audience</option>
        <option value="jti">JWT ID</option>
      </select>
      <input type="text" placeholder="Claim Name" class="input input-bordered w-full join-item" bind:value={claim.name} disabled={claim.disableName}/>
      {#if ["iat","exp","nbf"].includes(claim.name)}
        <div class="w-full">
          <!-- @ts-ignore -->
          <DatePicker bind:isOpen={claim.isPickerOpen} startDate={new Date()} onDayClick={dc => claim.value = `${Number(dc.startDate)/1000}`} enableFutureDates showTimePicker>
            <input type="text" placeholder="Claim Value" class="input input-bordered w-full join-item" bind:value={claim.value} on:click={()=>claim.isPickerOpen = true} />
          </DatePicker>
        </div>
        
      {:else}
        <input type="text" placeholder="Claim Value" class="input input-bordered w-full join-item" bind:value={claim.value} />
      {/if}
      <button class="btn btn-error join-item" on:click={() => claims = claims.filter(x=>x.idx !== claim.idx)}>X</button>
    </div>
  {/each}
  
  <button class="btn btn-primary w-full mb-4" on:click={generateJWT} disabled={disableGenerate}>Generate</button>
  <div class="text-xl" bind:this={tokenSpan}></div>
</form>
