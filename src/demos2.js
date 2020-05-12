/* DEMOS2 API Functions */
var DEMOS2 = function(ctx) {
    "use strict";

    /**
     * Creates an instance of DEMOS2
     *
     * @constructor
     * @this {DEMOS2}
     */
    var DEMOS2 = {
        DEMOS2_OK: 0,
        DEMOS2_FAIL: -1,

        BFS: ctx.BIG.MODBYTES,
        BGS: ctx.BIG.MODBYTES,

        /**
         * Convert byte array to string
         *
         * @this {DEMOS2}
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
         * @this {DEMOS2}
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
         * @this {DEMOS2}
         * @parameter m message to be hashedstring
         * @return ECP point
         */
        DEMOS2_hashit: function(m) {
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
         * @this {DEMOS2}
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
	    
            return this.DEMOS2_OK;
        },

        /**
         * Sign message
         *
         * @this {DEMOS2}
         * @parameter SIG Singature
         * @parameter m Message to sign
         * @parameter S Private key
         * @return Error code
         */
        sign(SIG, m, S) {
            var D = this.DEMOS2_hashit(m);
            var s = ctx.BIG.fromBytes(S);
            D = ctx.PAIR.G1mul(D, s);
            D.toBytes(SIG, true);
            return this.DEMOS2_OK;
        },

        /**
         * Verify message
         *
         * @this {DEMOS2}
         * @parameter SIG Signature
         * @parameter m Message to sign
         * @parameter W Public key
         * @return Error code
         */
        verify(SIG, m, W) {
            var HM = this.DEMOS2_hashit(m);
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
                return this.DEMOS2_OK;
            return this.DEMOS2_FAIL;
        },

        /**
         * R=R1+R2 in group G1 
         *
         * @this {DEMOS2}
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
         * @this {DEMOS2}
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

    return DEMOS2;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        DEMOS2: DEMOS2
    };
}
