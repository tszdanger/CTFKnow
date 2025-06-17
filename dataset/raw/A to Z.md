# MetaCTF 2021  
## A to Z (100pts)  
### Description:  
>This encrypted flag will only require a simple substitution cipher to solve.
Rearrange the letters from A to Z. `yzhsufo_rh_nb_uze_wdziu`

### Step 1 - Identify the Cipher (Or Don't?):  
When a cipher appears to be a quick substitution, like this one, I use [this
site](http://theblob.org/rot.cgi) to test out all possible letter shifts. It's
more effective than other tools in my opinion and more legible than dCode is.

```javascript  
ROT-0: yzhsufo_rh_nb_uze_wdziu  
ROT-1: zaitvgp_si_oc_vaf_xeajv  
ROT-2: abjuwhq_tj_pd_wbg_yfbkw  
ROT-3: bckvxir_uk_qe_xch_zgclx  
ROT-4: cdlwyjs_vl_rf_ydi_ahdmy  
ROT-5: demxzkt_wm_sg_zej_bienz  
ROT-6: efnyalu_xn_th_afk_cjfoa  
ROT-7: fgozbmv_yo_ui_bgl_dkgpb  
ROT-8: ghpacnw_zp_vj_chm_elhqc  
ROT-9: hiqbdox_aq_wk_din_fmird  
ROT-10: ijrcepy_br_xl_ejo_gnjse  
ROT-11: jksdfqz_cs_ym_fkp_hoktf  
ROT-12: kltegra_dt_zn_glq_iplug  
ROT-13: lmufhsb_eu_ao_hmr_jqmvh  
ROT-14: mnvgitc_fv_bp_ins_krnwi  
ROT-15: nowhjud_gw_cq_jot_lsoxj  
ROT-16: opxikve_hx_dr_kpu_mtpyk  
ROT-17: pqyjlwf_iy_es_lqv_nuqzl  
ROT-18: qrzkmxg_jz_ft_mrw_ovram  
ROT-19: rsalnyh_ka_gu_nsx_pwsbn  
ROT-20: stbmozi_lb_hv_oty_qxtco  
ROT-21: tucnpaj_mc_iw_puz_ryudp  
ROT-22: uvdoqbk_nd_jx_qva_szveq  
ROT-23: vweprcl_oe_ky_rwb_tawfr  
ROT-24: wxfqsdm_pf_lz_sxc_ubxgs  
ROT-25: xygrten_qg_ma_tyd_vcyht  
```  
Unfortunately, none of these look to be the answer. In this case, I resort to
one last substitution cipher before looking at crazy attacks: Atbash.

### Step 2 - Atbash Attack:  
Knowing different types of ciphers and being able to execute them is part of a
cryptographer's toolkit. I found Atbash long ago and reference it when I'm in
need of a substitution cipher. There's no easy way to identify it, but it
should be tried when dealing with substitution.  
Sure enough, using [CyberChef](https://gchq.github.io/CyberChef/) with an
Atbash recipe will output the flag.

For those completely unfamiliar with how to determine what ciphers to use,
resources like [this
list](http://practicalcryptography.com/ciphers/substitution-category/) of
substitution ciphers would be a good place to start. Testing all of them
wouldn't hurt.

<details>  
 <summary> Flag Spoiler </summary>  
 bashful_is_my_fav_dwarf  
</details>

## Learning Takeaways  
We learned that there are many different types of substitution ciphers besides
ROT and Caesar. By finding resources on ciphers, we can build out our own
toolkits to identify ciphers in the future and spend less time guessing.  

Original writeup
(https://github.com/team23ctf/writeups/blob/main/metactf2021/A%20to%20Z/A%20to%20Z.md).