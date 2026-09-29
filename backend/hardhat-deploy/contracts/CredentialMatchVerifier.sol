// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract CredentialMatchVerifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 18246332933763473366493585112342425696062049118239251986028692799196813203726;
    uint256 constant deltax2 = 14398490079961786772487134745417277212888951358696191493282411293512461000007;
    uint256 constant deltay1 = 11138740100205339678364007951753579116322749246569947552443617958705903006629;
    uint256 constant deltay2 = 21713542956941087103560070231461041658491727161502894085380539622717559875762;

    
    uint256 constant IC0x = 2987525953737612721354035507087468727319898898254356383175000909309368360126;
    uint256 constant IC0y = 105707019003962248802784053990350303516196644076451448122412432241713040151;
    
    uint256 constant IC1x = 4803561135301914143075902366853664269076722604127305196133917777750755528367;
    uint256 constant IC1y = 11666084319604917475238487822405495537740421793897129302993507103028501567119;
    
    uint256 constant IC2x = 4174755419074461691631070607716177585545610660466505029560165674315109789090;
    uint256 constant IC2y = 4476004825367244886730028495045223677301252301907017823083987674306884394588;
    
    uint256 constant IC3x = 2201641634532400798936613536076555061084577296703947418436367819020092857469;
    uint256 constant IC3y = 10594924522357721563017186514323586121870027997208998616760896924654404039236;
    
    uint256 constant IC4x = 11040360925850863471778690833567756081622273392822900622350793007935920143716;
    uint256 constant IC4y = 21321441467392649516925097743814514913317600833740266941941625922967852140601;
    
    uint256 constant IC5x = 7431634348137059026050667311347570088110639132736484135526250857340869258814;
    uint256 constant IC5y = 12540135433606638278545145054788514847315242048281406377041442836665829834225;
    
    uint256 constant IC6x = 2048510451423960118500738385117678495039928572708065114831688074940421101225;
    uint256 constant IC6y = 9758550252098923490309052125219515741840271056227476879942308884257558287752;
    
    uint256 constant IC7x = 6415012316747013151934096760061222601568561367911335289727622920112956684204;
    uint256 constant IC7y = 16058001188592761678312120513149550430288470974251645688076946845960629550729;
    
    uint256 constant IC8x = 995778472952287294816234083870027158143408213812571633653932427966225725112;
    uint256 constant IC8y = 5284513254578085757998114083860470448130083271694489567306169388665488752329;
    
    uint256 constant IC9x = 21340873397325709677957995161120886276369645092519452902277130053090684195556;
    uint256 constant IC9y = 20589321126866324299238705019179590194071589196894106576626301187118478219404;
    
    uint256 constant IC10x = 20624520264990410654558595361861584225853065854654075589616604918344505383982;
    uint256 constant IC10y = 2516045154689963566793197380581480327638077635530908406097202967950845544246;
    
    uint256 constant IC11x = 11954377229497910428791740300803331470322502340044609309804522921702330592130;
    uint256 constant IC11y = 1421177531441273315796276662369490617708018356714336764301522016454531181981;
    
    uint256 constant IC12x = 6602422351325428021009204782912684455365465897874944079012096785580341074332;
    uint256 constant IC12y = 12227128359582648839965529099617091011083741599487056409121685913908501975147;
    
    uint256 constant IC13x = 8142291174914273825935581451066026480170174417505441832255758039965352980678;
    uint256 constant IC13y = 8795351011803537693409875666991589963357775436254881270107344755131673826505;
    
    uint256 constant IC14x = 20845376815468357691749353432475215349323462521811181476706729869778722722268;
    uint256 constant IC14y = 21626148661940667732246662637301549196071826622347493631742096553774378121845;
    
    uint256 constant IC15x = 15910617312364214568687220473845133623032646384976447401761666910307993295475;
    uint256 constant IC15y = 17329886391191378825540914540742538653675076478796166238992279366217615534756;
    
    uint256 constant IC16x = 2037453533586610820790369178243388297080663093419468309096715156611689014767;
    uint256 constant IC16y = 17925967571890450906937309666161453097465788810380732561664641529211942955599;
    
    uint256 constant IC17x = 11425896527670036451081378310493027964033640400260552723624940192169616932727;
    uint256 constant IC17y = 18409667081096670796483388616422507688562547358240855337931718570479256411180;
    
    uint256 constant IC18x = 2026171213523308473105981641590105324366984280856009843432350655109291463595;
    uint256 constant IC18y = 20267957530857245131632106285556900492670481155504745401020320465906519121211;
    
    uint256 constant IC19x = 2229793949743540639455031545390087929393075125654081905651919150184110822566;
    uint256 constant IC19y = 16041406291850993968068006429762574975717195067765536859115877522085034514930;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[19] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
