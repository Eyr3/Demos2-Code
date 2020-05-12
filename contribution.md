新增

\examples\browser 中文件：
1. example_NIZK.html  Demos2论文中NIZK for DDH Tuple
2. example_Enc01.html Demos2论文中Proof a ciphertext encrypts 0 or 1
3. example_Enc1_ddh.html 用ddh证明一个(g1,h1,c1,c2/(g1^b))为ddh tuple，即证明b=1
4. example_Enc1_crsm.html 上述1的证明中crs \in G2与(A,B,C,D) \in G1在不同域上，这里增加crs_m \in G1，与(A,B,C,D)在同一域上

\examples\browser\src\bls.js 中函数