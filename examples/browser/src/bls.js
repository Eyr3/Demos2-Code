// This is just a sample script. Paste your real code (javascript or HTML) here.
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* BLS API Functions */
var BLS = function(ctx) {
    "use strict";

    /**
     * Creates an instance of BLS
     *
     * @constructor
     * @this {BLS}
     */
    var BLS = {
        BLS_OK: 0,
        BLS_FAIL: -1,

        BFS: ctx.BIG.MODBYTES,
        BGS: ctx.BIG.MODBYTES,

        /**
         * Convert byte array to string
         *
         * @this {BLS}
         * @parameter b byte array
         * @return string
         */
        bytestostring: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }

            return s;
        },

        /**
         * Convert string to byte array 
         *
         * @this {BLS}
         * @parameter s string
         * @return byte array
         */
        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        },


        /**
         *  hash a message to an ECP point, using SHA3 
         *
         * @this {BLS}
         * @parameter m message to be hashedstring
         * @return ECP point
         */
        bls_hashit: function(m) {
            var sh = new ctx.SHA3(ctx.SHA3.SHAKE256);
            var hm = [];
            var t = this.stringtobytes(m);
            for (var i = 0; i < t.length; i++)
                sh.process(t[i]);
            sh.shake(hm, this.BFS);
            var P = ctx.ECP.mapit(hm);
            return P;
        },

        /**
         * Generate key pair
         *
         * @this {BLS}
         * @parameter rng Cryptographically Secure Random Number Generator
         * @parameter S Private key. Generated externally if RNG set to NULL
         * @parameter W Public key
         * @return Error code
         */
        KeyPairGenerate(rng, S, W) {
            var G = ctx.ECP2.generator();
	        var s;
	    
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                s = ctx.BIG.randomnum(q, rng);
                s.toBytes(S);
            } else {
                s = ctx.BIG.fromBytes(S);
            }
	    
            G = ctx.PAIR.G2mul(G, s);
            G.toBytes(W);
	    
            return this.BLS_OK;
        },

        /**
         * Generate DDH Tuple
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @parameter S Private key. Generated externally if RNG set to NULL
         * @parameter DDH Tuple: {A,B,C,D} in G1
         */
        DDHTGen(rng,A,B,C,D,S) {
            var G = ctx.ECP.generator();
            var G1A, G1B, G1C, G1D;
            var a, b, s;

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            a = ctx.BIG.randomnum(q, rng);
            b = ctx.BIG.randomnum(q, rng);
            s = ctx.BIG.randomnum(q, rng);
            s.toBytes(S);
            
            G1A = ctx.PAIR.G1mul(G, a);
            G1A.toBytes(A);
            G1B = ctx.PAIR.G1mul(G, b);
            G1B.toBytes(B);

            G1C = ctx.PAIR.G1mul(G1A, s);
            G1C.toBytes(C);
            G1D = ctx.PAIR.G1mul(G1B, s);
            G1D.toBytes(D);

            return this.BLS_OK;
        },

        /**randomly generate A1,B1,C1,D1 */
        DDHTGentest(rng,A1,B1,C1,D1) {
            var G = ctx.ECP.generator();
            var G1A, G1B, G1C, G1D;
            var a, b, c, d;

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            a = ctx.BIG.randomnum(q, rng);
            b = ctx.BIG.randomnum(q, rng);
            c = ctx.BIG.randomnum(q, rng);
            d = ctx.BIG.randomnum(q, rng);
            
            G1A = ctx.PAIR.G1mul(G, a);
            G1A.toBytes(A1);
            G1B = ctx.PAIR.G1mul(G, b);
            G1B.toBytes(B1);

            G1C = ctx.PAIR.G1mul(G, c);
            G1C.toBytes(C1);
            G1D = ctx.PAIR.G1mul(G, d);
            G1D.toBytes(D1);

            return this.BLS_OK;
        },

        /**
         * Generate crs in G2
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @output crs={H2, u={U1,U2}}
         */
        CRSGen(rng,H2,U1,U2) {
            var G = ctx.ECP2.generator();
            var G2H2, G2U1, G2U2;
            var a1, a2;

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            a1 = ctx.BIG.randomnum(q, rng);
            a2 = ctx.BIG.randomnum(q, rng);

            G2H2 = ctx.PAIR.G2mul(G, a1);
            G2H2.toBytes(H2);

            G2U1 = ctx.PAIR.G2mul(G, a2);    
            G2U1.toBytes(U1);         

            G2U2 = ctx.PAIR.G2mul(G2H2, a2);
            G2U2.add(G);
            G2U2.toBytes(U2);

            return this.BLS_OK;
        },

        /**
         * Prov
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @parameter crs={H2, u={U1,U2}}, {A,B,C,D}, S Private key
         * @output pi={c={C1,C2}, P1,P2}
         * @tip A,B,C,D \in G1
         */
        Prov(H2,U1,U2,A,B,S,rng,C1,C2,P1,P2) {
            var G = ctx.ECP2.generator();
            var G2C1,G2C2,G1P1,G1P2;
            var tmp1, tmp2;
            var r;

            var s = ctx.BIG.fromBytes(S);
            var h2 = ctx.ECP2.fromBytes(H2);
            var u1 = ctx.ECP2.fromBytes(U1);
            var u2 = ctx.ECP2.fromBytes(U2);
            var G1A = ctx.ECP.fromBytes(A);
            var G1B = ctx.ECP.fromBytes(B);

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            r = ctx.BIG.randomnum(q, rng);

            G2C1 = ctx.PAIR.G2mul(u1, s);
            tmp1 = ctx.PAIR.G2mul(G, r);
            G2C1.add(tmp1);
            G2C1.toBytes(C1);

            G2C2 = ctx.PAIR.G2mul(u2, s);
            tmp2 = ctx.PAIR.G2mul(h2, r);
            G2C2.add(tmp2);
            G2C2.toBytes(C2);

            G1P1 = ctx.PAIR.G1mul(G1A, r);
            G1P1.toBytes(P1);

            G1P2 = ctx.PAIR.G1mul(G1B, r);
            G1P2.toBytes(P2);

            return this.BLS_OK;
        },


        /** Prov_2
         * @paramter (crs_m={mH1,mU1,mU2})
         * @output PI_crsm={mC1,mC2,mP1,mP2}
         * @tip A,B,C,D \in G2 
         */
        Prov_2(H1,U1,U2,A,B,S,rm,C1,C2,P1,P2) {
            var G1 = ctx.ECP.generator();
            var G1C1,G1C2,G2P1,G2P2;
            var tmp1, tmp2;
            
            var s = ctx.BIG.fromBytes(S);
            var h1 = ctx.ECP.fromBytes(H1);
            var u1 = ctx.ECP.fromBytes(U1);
            var u2 = ctx.ECP.fromBytes(U2);
            var a = ctx.ECP2.fromBytes(A);
            var b = ctx.ECP2.fromBytes(B);

            G1C1 = ctx.PAIR.G1mul(u1, s);
            tmp1 = ctx.PAIR.G1mul(G1, rm);
            G1C1.add(tmp1);
            G1C1.toBytes(C1);

            G1C2 = ctx.PAIR.G1mul(u2, s);
            tmp2 = ctx.PAIR.G1mul(h1, rm);
            G1C2.add(tmp2);
            G1C2.toBytes(C2);
            
            G2P1 = ctx.PAIR.G2mul(a, rm);
            G2P1.toBytes(P1);
            
            G2P2 = ctx.PAIR.G2mul(b, rm);
            G2P2.toBytes(P2);

            return this.BLS_OK;
        },


        /**
         * Verify
         *
         * @parameter 
         * @parameter crs={H2, u={U1,U2}}, {A,B,C,D}, pi={c={C1,C2}, P1,P2}
         * @tip A,B,C,D \in G2
         */
        //Vrfy(H2,U1,U2,A,B,C,D,C1,C2,P1,P2) {
        Vrfy(H2,U1,U2,A,B,C,D,C1,C2,P1,P2) {
            var G = ctx.ECP2.generator();
            
            var aux11 = new ctx.FP12(0),
                aux21 = new ctx.FP12(0),
                aux12 = new ctx.FP12(0),
                aux22 = new ctx.FP12(0),
                aux13 = new ctx.FP12(0),
                aux23 = new ctx.FP12(0),
                aux14 = new ctx.FP12(0),
                aux24 = new ctx.FP12(0);
            
            var h2 = ctx.ECP2.fromBytes(H2);
            var u1 = ctx.ECP2.fromBytes(U1);
            var u2 = ctx.ECP2.fromBytes(U2);  
            var G1A = ctx.ECP.fromBytes(A);
            var G1B = ctx.ECP.fromBytes(B);
            var G1C = ctx.ECP.fromBytes(C);
            var G1D = ctx.ECP.fromBytes(D);
            var c1 = ctx.ECP2.fromBytes(C1);
            var c2 = ctx.ECP2.fromBytes(C2);
            var pi1 = ctx.ECP.fromBytes(P1);
            var pi2 = ctx.ECP.fromBytes(P2);
            
            aux21 = ctx.PAIR.ate2(u1,G1C,G,pi1);
            aux21 = ctx.PAIR.fexp(aux21);
            aux11 = ctx.PAIR.ate(c1,G1A);
            aux11 = ctx.PAIR.fexp(aux11);     

            aux22 = ctx.PAIR.ate2(u2,G1C,h2,pi1);
            aux22 = ctx.PAIR.fexp(aux22);
            aux12 = ctx.PAIR.ate(c2,G1A);
            aux12 = ctx.PAIR.fexp(aux12);

            aux23 = ctx.PAIR.ate2(u1,G1D,G,pi2);
            aux23 = ctx.PAIR.fexp(aux23);
            aux13 = ctx.PAIR.ate(c1,G1B);
            aux13 = ctx.PAIR.fexp(aux13);

            aux24 = ctx.PAIR.ate2(u2,G1D,h2,pi2);
            aux24 = ctx.PAIR.fexp(aux24);
            aux14 = ctx.PAIR.ate(c2,G1B);
            aux14 = ctx.PAIR.fexp(aux14);
            
            if ( aux21.toString() == aux11.toString() )
                if ( aux22.toString() == aux12.toString() )
                    if ( aux23.toString() == aux13.toString() )
                        if ( aux24.toString() == aux14.toString() )
                            return this.BLS_OK;
                        return this.BLS_FAIL;
        },

        /**
         * Verify_2
         *
         * @parameter 
         * @parameter crs={H1, u={U1,U2}}, {A,B,C,D}, pi={c={C1,C2}, P1,P2}
         * @tip A,B,C,D \in G2
         */
        //Vrfy(crs_m)
        Vrfy_2(H1,U1,U2,A,B,C,D,C1,C2,P1,P2) {
            var G1 = ctx.ECP.generator();
            var aux11 = new ctx.FP12(0),
                aux21 = new ctx.FP12(0),
                aux12 = new ctx.FP12(0),
                aux22 = new ctx.FP12(0),
                aux13 = new ctx.FP12(0),
                aux23 = new ctx.FP12(0),
                aux14 = new ctx.FP12(0),
                aux24 = new ctx.FP12(0);
        
            var h1 = ctx.ECP.fromBytes(H1);
            var u1 = ctx.ECP.fromBytes(U1);
            var u2 = ctx.ECP.fromBytes(U2);
            var c1 = ctx.ECP.fromBytes(C1);
            var c2 = ctx.ECP.fromBytes(C2);
            var p1 = ctx.ECP2.fromBytes(P1);
            var p2 = ctx.ECP2.fromBytes(P2);
            var a = ctx.ECP2.fromBytes(A);
            var b = ctx.ECP2.fromBytes(B);
            var c = ctx.ECP2.fromBytes(C);
            var d = ctx.ECP2.fromBytes(D);
            
            aux21 = ctx.PAIR.ate2(c,u1,p1,G1);
            aux21 = ctx.PAIR.fexp(aux21);
            aux11 = ctx.PAIR.ate(a,c1);
            aux11 = ctx.PAIR.fexp(aux11);     
            
            aux22 = ctx.PAIR.ate2(c,u2,p1,h1);
            aux22 = ctx.PAIR.fexp(aux22);
            aux12 = ctx.PAIR.ate(a,c2);
            aux12 = ctx.PAIR.fexp(aux12);
            
            aux23 = ctx.PAIR.ate2(d,u1,p2,G1);
            aux23 = ctx.PAIR.fexp(aux23);
            aux13 = ctx.PAIR.ate(b,c1);
            aux13 = ctx.PAIR.fexp(aux13);
            
            aux24 = ctx.PAIR.ate2(d,u2,p2,h1);
            aux24 = ctx.PAIR.fexp(aux24);
            aux14 = ctx.PAIR.ate(b,c2);
            aux14 = ctx.PAIR.fexp(aux14);
        
            if ( (aux21.toString() == aux11.toString()) &&
                (aux22.toString() == aux12.toString()) &&
                (aux23.toString() == aux13.toString()) &&
                (aux24.toString() == aux14.toString()) )
                return this.BLS_OK;  
            else return this.BLS_FAIL;
        
        },


        /**
         * Simulate Generate crs*
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @output crs*={SH2, u={SU1,SU2}}, td=a2
         */
        SimCRSGen(rng,SH2,SU1,SU2,A2) {
            var G = ctx.ECP2.generator();
            var G2H2, G2U1, G2U2;
            var a1, a2;

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            a1 = ctx.BIG.randomnum(q, rng);
            a2 = ctx.BIG.randomnum(q, rng);
            a2.toBytes(A2);

            G2H2 = ctx.PAIR.G2mul(G, a1);
            G2H2.toBytes(SH2);

            G2U1 = ctx.PAIR.G2mul(G, a2);    
            G2U1.toBytes(SU1);         

            G2U2 = ctx.PAIR.G2mul(G2H2, a2);
            G2U2.toBytes(SU2);

            return this.BLS_OK;
        },

        /**
         * Simulate Prov
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @parameter crs*={SH2, u={SU1,SU2}}, {A,B,C,D}, td=a2
         * @output pi*={c*={SC1,SC2}, SP1,SP2}
         * @tip (A,B,C,D) \in G2
         */
        SimProv(SH2,A,B,C,D,rng,SC1,SC2,SP1,SP2,A2) {
            var G = ctx.ECP2.generator();
            var G2C1,G2C2,G1P1,G1P2;
            var tmp1, tmp2;
            var r;

            var a2 = ctx.BIG.fromBytes(A2);
            var h2 = ctx.ECP2.fromBytes(SH2);
            var G1A = ctx.ECP.fromBytes(A);
            var G1B = ctx.ECP.fromBytes(B);
            var G1C = ctx.ECP.fromBytes(C);
            var G1D = ctx.ECP.fromBytes(D);

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            r = ctx.BIG.randomnum(q, rng);

            G2C1 = ctx.PAIR.G2mul(G, r);
            G2C1.toBytes(SC1);

            G2C2 = ctx.PAIR.G2mul(h2, r);
            G2C2.toBytes(SC2);

            G1P1 = ctx.PAIR.G1mul(G1A, r);
            tmp1 = ctx.PAIR.G1mul(G1C, a2);
            G1P1.sub(tmp1)
            G1P1.toBytes(SP1);

            G1P2 = ctx.PAIR.G1mul(G1B, r);
            tmp2 = ctx.PAIR.G1mul(G1D, a2);
            G1P2.sub(tmp2)
            G1P2.toBytes(SP2);

            return this.BLS_OK;
        },

        
        /** Sim_Prov_2
         * @parameter (crs_m={smH1,smU1,smU2};(g2,h2,su1,su2/g2);td)
         * @output PI_crsm={smC1,smC2,smP1,smP2}
         * @tip (A,B,C,D) \in G2
         */
        SimProv_2(H1,A,B,C,D,TD,rm,SC1,SC2,SP1,SP2) {
            var G1C1,G1C2,G2P1,G2P2;
            var tmp1, tmp2;
            var G1 = ctx.ECP.generator();
            
            var sh1 = ctx.ECP.fromBytes(H1);
            var td = ctx.BIG.fromBytes(TD);
            var a = ctx.ECP2.fromBytes(A);
            var b = ctx.ECP2.fromBytes(B);
            var c = ctx.ECP2.fromBytes(C);
            var d = ctx.ECP2.fromBytes(D);

            G1C1 = ctx.PAIR.G1mul(G1, rm);
            G1C1.toBytes(SC1);

            G1C2 = ctx.PAIR.G1mul(sh1, rm);
            G1C2.toBytes(SC2);
            
            G2P1 = ctx.PAIR.G2mul(a, rm);
            tmp1 = ctx.PAIR.G2mul(c, td);
            G2P1.sub(tmp1);
            G2P1.toBytes(SP1);
            
            G2P2 = ctx.PAIR.G2mul(b, rm);
            tmp2 = ctx.PAIR.G2mul(d, td);
            G2P2.sub(tmp2);
            G2P2.toBytes(SP2);

            return this.BLS_OK;
        },


//--------------------------------------------------------------------
        /**
         * Generate pk=(g1,f1)
         *
         * @this {BLS}
         * @parameter rng Cryptographically Secure Random Number Generator
         * @parameter S Private key. Generated externally if RNG set to NULL
         * @parameter F1 Public key
         */
        PKGen(rng, S, F1) {
            var G = ctx.ECP.generator();
	        var s;
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            s = ctx.BIG.randomnum(q, rng);
            s.toBytes(S);

            var f1 = ctx.PAIR.G1mul(G, s);
            f1.toBytes(F1);
	    
            return this.BLS_OK;
        },

        /**
         * Generate r,c={c1,c2} in G1
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @output r, c={C1,C2}
         */
        CRGen(rng, F1, B, R, C1, C2) {
            var G = ctx.ECP.generator();
            var r;
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            r = ctx.BIG.randomnum(q, rng);
            r.toBytes(R);

            var c1 = ctx.PAIR.G1mul(G, r);
            c1.toBytes(C1);

            var f1 = ctx.ECP.fromBytes(F1);
            var c2 = ctx.PAIR.G1mul(f1, r);
            var b = ctx.BIG.fromBytes(B);   //b=0 or 1
            var gb = ctx.PAIR.G1mul(G, b);
            c2.add(gb)
            c2.toBytes(C2);

            return this.BLS_OK;
        },

        /**
         * Generate crs_m in G1
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @output crs_m={H1, u={U1,U2}}
         */
        CRSGen01(rng,mH1,mU1,mU2) {
            var G = ctx.ECP.generator();
            var G1H1, G1U1, G1U2;
            var a1, a2;

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            a1 = ctx.BIG.randomnum(q, rng);
            a2 = ctx.BIG.randomnum(q, rng);

            G1H1 = ctx.PAIR.G1mul(G, a1);
            G1H1.toBytes(mH1);

            G1U1 = ctx.PAIR.G1mul(G, a2);    
            G1U1.toBytes(mU1);         

            G1U2 = ctx.PAIR.G1mul(G1H1, a2);
            G1U2.add(G);
            G1U2.toBytes(mU2);

            return this.BLS_OK;
        },
        
        /**
         * Prov01
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @parameter crs={H2, u={U1,U2}}, {A,B,C,D}, S Private key
         * @output pi={c={C1,C2}, P1,P2}
         */
        Prov01(mH1,mU1,mU2,F1,C1,C2,B,R,rng,H2,b1U1,b1U2,b2U1,b2U2,mC1,mC2,mP1,mP2,b1C1,b1C2,b1P1,b1P2,b2C1,b2C2,b2P1,b2P2,U1,U2) {
            var g1=[], g2=[];
            var G1 = ctx.ECP.generator();
            G1.toBytes(g1);
            var G2 = ctx.ECP2.generator();
            G2.toBytes(g2);

            var u1b,u2b,u1_b,u2_b;
            var a1,a2,a3;
            var A3=[];

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            a1 = ctx.BIG.randomnum(q, rng);
            a2 = ctx.BIG.randomnum(q, rng);
            a3 = ctx.BIG.randomnum(q, rng);
            a3.toBytes(A3);
            var a23 = new ctx.BIG(0);
            a23.copy(a2);
            a23.add(a3);
            
            var h2 = ctx.PAIR.G2mul(G2, a1);
            h2.toBytes(H2);
            //u(b)
            u1b = ctx.PAIR.G2mul(G2, a2);
            u1b.toBytes(b1U1);
            u2b = ctx.PAIR.G2mul(h2, a2);
            u2b.add(G2);
            u2b.toBytes(b1U2);
            //u(1-b)
            u1_b = ctx.PAIR.G2mul(G2, a3);
            u1_b.toBytes(b2U1);
            u2_b = ctx.PAIR.G2mul(h2, a3);
            u2_b.toBytes(b2U2);
            
            var u1 = new ctx.ECP2(0),
                u2 = new ctx.ECP2(0);
            u1.copy(u1b);
            u1.add(u1_b);
            u1.toBytes(U1);
            u2.copy(u2b);
            u2.add(u2_b);
            u2.toBytes(U2);
            
            /** Prov(crs_m={mH1,mU1,mU2})
             * output: PI_crsm={mC1,mC2,mP1,mP2}
             */
            var G1C1,G1C2,G1P1,G1P2;
            var tmp1, tmp2;
            var rm = ctx.BIG.randomnum(q, rng);
            var h1 = ctx.ECP.fromBytes(mH1);
            var mu1 = ctx.ECP.fromBytes(mU1);
            var mu2 = ctx.ECP.fromBytes(mU2);
            
            G1C1 = ctx.PAIR.G1mul(mu1, a23);
            tmp1 = ctx.PAIR.G1mul(G1, rm);
            G1C1.add(tmp1);
            G1C1.toBytes(mC1);

            G1C2 = ctx.PAIR.G1mul(mu2, a23);
            tmp2 = ctx.PAIR.G1mul(h1, rm);
            G1C2.add(tmp2);
            G1C2.toBytes(mC2);

            G1P1 = ctx.PAIR.G2mul(G2, rm);
            G1P1.toBytes(mP1);

            G1P2 = ctx.PAIR.G2mul(h2, rm);
            G1P2.toBytes(mP2);

            /** Prov(crs_b={H2,b1U1,b1U2},r)
             * output: PI_b={b1C1,b1C2,b1P1,b1P2}
             */
            this.Prov(H2,b1U1,b1U2,g1,F1,R,rng,b1C1,b1C2,b1P1,b1P2);

            /** SimProv(crs_1-b={H2,b2U1,b2U2},a3)
             * output: PI_1-b={b2C1,b2C2,b2P1,b2P2}
             */

            var b = ctx.BIG.fromBytes(B);
            var BIG1 = new ctx.BIG(1);
            BIG1.sub(b);
            var subb = ctx.PAIR.G1mul(G1, BIG1);
            var c2 = ctx.ECP.fromBytes(C2);
            c2.sub(subb);
            var C2_G1 = [];
            c2.toBytes(C2_G1);
            this.SimProv(H2,g1,F1,C1,C2_G1,rng,b2C1,b2C2,b2P1,b2P2,A3);

            return this.BLS_OK;
        },

        /**
         * Verify
         *
         * @parameter 
         * @parameter crs={H2, u={U1,U2}}, {A,B,C,D}, pi={c={C1,C2}, P1,P2}
         */
        Vrfy01(mH1,mU1,mU2,H2,U1,U2,mC1,mC2,mP1,mP2,B,F1,C1,C2,b1U1,b1U2,b1C1,b1C2,b1P1,b1P2,b2U1,b2U2,b2C1,b2C2,b2P1,b2P2) {
            var g1=[], g2=[];
            var G1 = ctx.ECP.generator();
            G1.toBytes(g1);
            var G2 = ctx.ECP2.generator();
            G2.toBytes(g2);
           
            //Vrfy_2(crs_m)
            var u2_g2 = ctx.ECP2.fromBytes(U2);
            var U2_G2 = [];
            u2_g2.sub(G2);
            u2_g2.toBytes(U2_G2);
            var res1 = this.Vrfy_2(mH1,mU1,mU2,g2,H2,U1,U2_G2,mC1,mC2,mP1,mP2);
            mywindow.document.write("res for crsm:"+res1+" <br>");

            var b = ctx.BIG.fromBytes(B);
            if (b==0) {
                var res2=this.Vrfy(H2,b1U1,b1U2,g1,F1,C1,C2,b1C1,b1C2,b1P1,b1P2);
                mywindow.document.write("res for crs(0):"+res2+" <br>");

                var c2_g1 = ctx.ECP.fromBytes(C2);
                c2_g1.sub(G1);
                var C2G1 = [];
                c2_g1.toBytes(C2G1);
                var res3=this.Vrfy(H2,b2U1,b2U2,g1,F1,C1,C2G1,b2C1,b2C2,b2P1,b2P2);
                mywindow.document.write("res for crs(1):"+res3+" <br>");
            }
            else {  //b=1 or others
                var res2=this.Vrfy(H2,b2U1,b2U2,g1,F1,C1,C2,b2C1,b2C2,b2P1,b2P2);
                mywindow.document.write("res for crs(1):"+res2+" <br>");
                
                var c2_g1 = ctx.ECP.fromBytes(C2);
                c2_g1.sub(G1);
                var C2G1 = [];
                c2_g1.toBytes(C2G1);
                var res3=this.Vrfy(H2,b1U1,b1U2,g1,F1,C1,C2G1,b1C1,b1C2,b1P1,b1P2);
                mywindow.document.write("res for crs(0):"+res3+" <br>");
            }

            if (res1==0 && res2==0 && res3==0)
                return this.BLS_OK;
            else return this.BLS_FAIL;
        },


        /**
         * SimVerify01
         * 因为verify sim时，由于不存在b=0/1，crs_1,crs_0已确定，所以不需要判断b=0/1做不同决定。如果需要用Verfy()函数，需要在语句前定义b=0
         *
         * @parameter 
         * @parameter crs={H2, u={U1,U2}}, {A,B,C,D}, pi={c={C1,C2}, P1,P2}
         */
        SimVrfy01(mH1,mU1,mU2,H2,U1,U2,mC1,mC2,mP1,mP2,F1,C1,C2,b1U1,b1U2,b1C1,b1C2,b1P1,b1P2,b2U1,b2U2,b2C1,b2C2,b2P1,b2P2) {
            var g1=[], g2=[];
            var G1 = ctx.ECP.generator();
            G1.toBytes(g1);
            var G2 = ctx.ECP2.generator();
            G2.toBytes(g2);
           
            //Vrfy_2(crs_m)
            var u2_g2 = ctx.ECP2.fromBytes(U2);
            var U2_G2 = [];
            u2_g2.sub(G2);
            u2_g2.toBytes(U2_G2);
            var res1 = this.Vrfy_2(mH1,mU1,mU2,g2,H2,U1,U2_G2,mC1,mC2,mP1,mP2);
            mywindow.document.write("res for crsm:"+res1+" <br>");

            var res2=this.Vrfy(H2,b1U1,b1U2,g1,F1,C1,C2,b1C1,b1C2,b1P1,b1P2);
            mywindow.document.write("res for crs(0):"+res2+" <br>");

            var c2_g1 = ctx.ECP.fromBytes(C2);
            c2_g1.sub(G1);
            var C2G1 = [];
            c2_g1.toBytes(C2G1);
            var res3=this.Vrfy(H2,b2U1,b2U2,g1,F1,C1,C2G1,b2C1,b2C2,b2P1,b2P2);
            mywindow.document.write("res for crs(1):"+res3+" <br>");

            if (res1==0 && res2==0 && res3==0)
                return this.BLS_OK;
            else return this.BLS_FAIL;
        },


        /**
         * Simulate Generate crs* in Encrypt(0,1,...)
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @output crs*={smH2, u={smU1,smU2}}, td=a2
         */
        SimCRSGen01(rng,smH1,smU1,smU2,TD) {
            var G = ctx.ECP.generator();
            var G1H1, G1U1, G1U2;
            var a1, a2;

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            a1 = ctx.BIG.randomnum(q, rng);
            a2 = ctx.BIG.randomnum(q, rng);
            a2.toBytes(TD);

            G1H1 = ctx.PAIR.G1mul(G, a1);
            G1H1.toBytes(smH1);

            G1U1 = ctx.PAIR.G1mul(G, a2);    
            G1U1.toBytes(smU1);         

            G1U2 = ctx.PAIR.G1mul(G1H1, a2);
            G1U2.toBytes(smU2);

            return this.BLS_OK;
        },

        /**
         * SimProv01 Enc(0, 1 or others)
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @parameter crs={H2, u={U1,U2}}, {A,B,C,D}, S Private key
         * @output pi={c={C1,C2}, P1,P2}
         */
        SimProv01(smH1,F1,C1,C2,TD,rng,SH2,U01,U02,U11,U12,SU1,SU2,smC1,smC2,smP1,smP2,S0C1,S0C2,S0P1,S0P2,S1C1,S1C2,S1P1,S1P2) {
            var g1=[], g2=[];
            var G1 = ctx.ECP.generator();
            G1.toBytes(g1);
            var G2 = ctx.ECP2.generator();
            G2.toBytes(g2);

            var u01,u02,u11,u12;
            var a1,a2,a3;
            var A2=[],A3=[];
            
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            a1 = ctx.BIG.randomnum(q, rng);
            a2 = ctx.BIG.randomnum(q, rng);
            a2.toBytes(A2);
            a3 = ctx.BIG.randomnum(q, rng);
            a3.toBytes(A3);
            
            var h2 = ctx.PAIR.G2mul(G2, a1);
            h2.toBytes(SH2);
            //u(0)
            u01 = ctx.PAIR.G2mul(G2, a2);
            u01.toBytes(U01);
            u02 = ctx.PAIR.G2mul(h2, a2);
            u02.toBytes(U02);
            //u(1)
            u11 = ctx.PAIR.G2mul(G2, a3);
            u11.toBytes(U11);
            u12 = ctx.PAIR.G2mul(h2, a3);
            u12.toBytes(U12);
            
            var u1 = new ctx.ECP2(0),
                u2 = new ctx.ECP2(0);
            u1.copy(u01);
            u1.add(u11);
            u1.toBytes(SU1);
            u2.copy(u02);
            u2.add(u12);
            u2.toBytes(SU2);
            
            /** Prov(crs_m={smH1,smU1,smU2})
             * output: PI_crsm={smC1,smC2,smP1,smP2}
            
            var G1C1,G1C2,G1P1,G1P2;
            var tmp1, tmp2;
            
            var smh1 = ctx.ECP.fromBytes(smH1);
            var td = ctx.BIG.fromBytes(TD);

            G1C1 = ctx.PAIR.G1mul(G1, rm);
            G1C1.toBytes(smC1);

            G1C2 = ctx.PAIR.G1mul(smh1, rm);
            G1C2.toBytes(smC2);
            
            G1P1 = ctx.PAIR.G2mul(G2, rm);
            tmp1 = ctx.PAIR.G2mul(u1, td);
            G1P1.sub(tmp1);
            G1P1.toBytes(smP1);
            
            G1P2 = ctx.PAIR.G2mul(h2, rm); */

            var rm = ctx.BIG.randomnum(q, rng);
            var su2_g2 = ctx.ECP2.fromBytes(SU2);
            var SU2_G2 = [];
            su2_g2.sub(G2);
            su2_g2.toBytes(SU2_G2);
            
            this.SimProv_2(smH1,g2,SH2,SU1,SU2_G2,TD,rm,smC1,smC2,smP1,smP2);

            /** SimProv(crs_b={H2,b1U1,b1U2},r)
             * output: PI_b={b1C1,b1C2,b1P1,b1P2}
             */
            this.SimProv(SH2,g1,F1,C1,C2,rng,S0C1,S0C2,S0P1,S0P2,A2);
            
            /** SimProv(crs_1-b={H2,b2U1,b2U2},a3)
             * output: PI_1-b={b2C1,b2C2,b2P1,b2P2}
             */
            var c2 = ctx.ECP.fromBytes(C2);
            c2.sub(G1);
            var C2_G1 = [];
            c2.toBytes(C2_G1);
            this.SimProv(SH2,g1,F1,C1,C2_G1,rng,S1C1,S1C2,S1P1,S1P2,A3);
            
            return this.BLS_OK;
        },

        /**
         * Prov1 Enc(1 or not1)
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @parameter crs={H2, u={U1,U2}}, {A,B,C,D}, S Private key
         * @output pi={c={C1,C2}, P1,P2}
         */
        Prov1(mH1,mU1,mU2,F1,R,rng,H2,U1,U2,mC1,mC2,mP1,mP2,bC1,bC2,bP1,bP2) {
            var g1=[], g2=[];
            var G1 = ctx.ECP.generator();
            G1.toBytes(g1);
            var G2 = ctx.ECP2.generator();
            G2.toBytes(g2);

            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            
            //this.CRSGen(rng,H2,U1,U2)
            var G2H2, G2U1, G2U2;

            var a1 = ctx.BIG.randomnum(q, rng);
            var a2 = ctx.BIG.randomnum(q, rng);
            var A2 = [];
            a2.toBytes(A2);

            G2H2 = ctx.PAIR.G2mul(G2, a1);
            G2H2.toBytes(H2);
            
            G2U1 = ctx.PAIR.G2mul(G2, a2);
            G2U1.toBytes(U1);         
            
            G2U2 = ctx.PAIR.G2mul(G2H2, a2);
            G2U2.add(G2);
            G2U2.toBytes(U2);
            
            /** Prov_2(crs_m={mH1,mU1,mU2})
             * output: PI_crsm={mC1,mC2,mP1,mP2}
            */
            var rm = ctx.BIG.randomnum(q, rng);
            this.Prov_2(mH1,mU1,mU2,g2,H2,A2,rm,mC1,mC2,mP1,mP2);

            /** Prov(crs_b={H2,U1,U2},r)
             * output: PI_b={bC1,bC2,bP1,bP2}
             */
            this.Prov(H2,U1,U2,g1,F1,R,rng,bC1,bC2,bP1,bP2);

            return this.BLS_OK;
        },

        /**
         * Verify Enc(1 or not1)
         *
         * @parameter 
         * @parameter crs={H2, u={U1,U2}}, {A,B,C,D}, pi={c={C1,C2}, P1,P2}
         */
        Vrfy1(mH1,mU1,mU2,H2,U1,U2,mC1,mC2,mP1,mP2,F1,C1,C2,bC1,bC2,bP1,bP2) {
            var g1=[], g2=[];
            var G1 = ctx.ECP.generator();
            G1.toBytes(g1);
            var G2 = ctx.ECP2.generator();
            G2.toBytes(g2);
           
            //Vrfy(crs_m)
            var aux11 = new ctx.FP12(0),
                aux21 = new ctx.FP12(0),
                aux12 = new ctx.FP12(0),
                aux22 = new ctx.FP12(0),
                aux13 = new ctx.FP12(0),
                aux23 = new ctx.FP12(0),
                aux14 = new ctx.FP12(0),
                aux24 = new ctx.FP12(0);
            
            var h2 = ctx.ECP2.fromBytes(H2);
            var u1 = ctx.ECP2.fromBytes(U1);
            var u2 = ctx.ECP2.fromBytes(U2);
            var h1 = ctx.ECP.fromBytes(mH1);
            var mu1 = ctx.ECP.fromBytes(mU1);
            var mu2 = ctx.ECP.fromBytes(mU2);
            var mc1 = ctx.ECP.fromBytes(mC1);
            var mc2 = ctx.ECP.fromBytes(mC2);
            var mp1 = ctx.ECP2.fromBytes(mP1);
            var mp2 = ctx.ECP2.fromBytes(mP2);

            aux21 = ctx.PAIR.ate2(u1,mu1,mp1,G1);
            aux21 = ctx.PAIR.fexp(aux21);
            aux11 = ctx.PAIR.ate(G2,mc1);
            aux11 = ctx.PAIR.fexp(aux11);     
            
            aux22 = ctx.PAIR.ate2(u1,mu2,mp1,h1);
            aux22 = ctx.PAIR.fexp(aux22);
            aux12 = ctx.PAIR.ate(G2,mc2);
            aux12 = ctx.PAIR.fexp(aux12);
            
            var u2_g2 = new ctx.ECP2(0);
            u2_g2.copy(u2);
            u2_g2.sub(G2);
            aux23 = ctx.PAIR.ate2(u2_g2,mu1,mp2,G1);
            aux23 = ctx.PAIR.fexp(aux23);
            aux13 = ctx.PAIR.ate(h2,mc1);
            aux13 = ctx.PAIR.fexp(aux13);
            
            aux24 = ctx.PAIR.ate2(u2_g2,mu2,mp2,h1);
            aux24 = ctx.PAIR.fexp(aux24);
            aux14 = ctx.PAIR.ate(h2,mc2);
            aux14 = ctx.PAIR.fexp(aux14);
            
            if ( (aux21.toString() == aux11.toString()) &&
                (aux22.toString() == aux12.toString()) &&
                (aux23.toString() == aux13.toString()) &&
                (aux24.toString() == aux14.toString()) )
                var res1 = 0;
            else var res1 = -1;
            //mywindow.document.write("res1:"+res1+" <br>");
            
            var c2_g1 = ctx.ECP.fromBytes(C2);
            c2_g1.sub(G1);
            var C2G1 = [];
            c2_g1.toBytes(C2G1);
            var res2=this.Vrfy(H2,U1,U2,g1,F1,C1,C2G1,bC1,bC2,bP1,bP2);
            //mywindow.document.write("res2:"+res2+" <br>");
            
            if (res1==0 && res2==0)
                return this.BLS_OK;
            else return this.BLS_FAIL;
        },


        /**
         * SimProv1 Enc(1 or not1)
         *
         * @parameter rng Cryptographically Secure Random Number Generator
         * @parameter crs={H2, u={U1,U2}}, {A,B,C,D}, S Private key
         * @output pi={c={C1,C2}, P1,P2}
         */
        SimProv1(smH1,F1,C1,C2,TD,rng,SH2,SU1,SU2,smC1,smC2,smP1,smP2,S1C1,S1C2,S1P1,S1P2) {
            var g1=[], g2=[];
            var G1 = ctx.ECP.generator();
            G1.toBytes(g1);
            var G2 = ctx.ECP2.generator();
            G2.toBytes(g2);

            var A2=[];
            
            var q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            this.SimCRSGen(rng,SH2,SU1,SU2,A2);
            
            /** Prov(crs_m={smH1,smU1,smU2};(g2,h2,su1,su2/g2);td)
             * output: PI_crsm={smC1,smC2,smP1,smP2}
             */
            var rm = ctx.BIG.randomnum(q, rng);
            var u2_g2 = ctx.ECP2.fromBytes(SU2);
            var U2_G2 = [];
            u2_g2.sub(G2);
            u2_g2.toBytes(U2_G2);
            this.SimProv_2(smH1,g2,SH2,SU1,U2_G2,TD,rm,smC1,smC2,smP1,smP2);
            
            /** SimProv(crs*={SH2,SU1,SU2},(g1,f1,c1,c2/g1),a2)
             * output: PI_1={S1C1,S1C2,S1P1,S1P2}
             */
            var c2 = ctx.ECP.fromBytes(C2);
            c2.sub(G1);
            var C2_G1 = [];
            c2.toBytes(C2_G1);
            this.SimProv(SH2,g1,F1,C1,C2_G1,rng,S1C1,S1C2,S1P1,S1P2,A2);
            
            return this.BLS_OK;
        },


//--------------------------------------------------------------------
        /**
         * Sign message
         *
         * @this {BLS}
         * @parameter SIG Singature
         * @parameter m Message to sign
         * @parameter S Private key
         * @return Error code
         */
        sign(SIG, m, S) {
            var D = this.bls_hashit(m);
            var s = ctx.BIG.fromBytes(S);
            D = ctx.PAIR.G1mul(D, s);
            D.toBytes(SIG, true);
            return this.BLS_OK;
        },

        /**
         * Verify message
         *
         * @this {BLS}
         * @parameter SIG Signature
         * @parameter m Message to sign
         * @parameter W Public key
         * @return Error code
         */
        verify(SIG, m, W) {
            var HM = this.bls_hashit(m);
            var D = ctx.ECP.fromBytes(SIG);
            var G = ctx.ECP2.generator();
            var PK = ctx.ECP2.fromBytes(W);
            D.neg();

            // Use new multi-pairing mechanism 
            var r = ctx.PAIR.initmp();
            ctx.PAIR.another(r, G, D);
            ctx.PAIR.another(r, PK, HM);
            var v = ctx.PAIR.miller(r);

            //.. or alternatively
            //			var v=ctx.PAIR.ate2(G,D,PK,HM);

            v = ctx.PAIR.fexp(v);
            if (v.isunity())
                return this.BLS_OK;
            return this.BLS_FAIL;
        },

        /**
         * R=R1+R2 in group G1 
         *
         * @this {BLS}
         * @parameter R1 G1 Point
         * @parameter R2 G1 Point
         * @parameter R G1 Point
         * @return Error code
         */
        add_G1(R1, R2, R) {
            var P = ctx.ECP.fromBytes(R1),
                Q = ctx.ECP.fromBytes(R2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(R, true);

            return 0;
        },

        /**
         *  W=W1+W2 in group G2 
         *
         * @this {BLS}
         * @parameter W1 G2 Point
         * @parameter W2 G2 Point
         * @parameter R G2 Point
         * @return Error code
         */
        add_G2(W1, W2, W) {
            var P = ctx.ECP2.fromBytes(W1),
                Q = ctx.ECP2.fromBytes(W2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(W);

            return 0;
        }

    };

    return BLS;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        BLS: BLS
    };
}
