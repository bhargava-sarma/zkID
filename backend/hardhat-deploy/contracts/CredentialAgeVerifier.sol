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

contract CredentialAgeVerifier {
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
    uint256 constant deltax1 = 3638296171157662791180012092699765943957100305147477904235893741881027495500;
    uint256 constant deltax2 = 12336482379151991122341821064837431149587220645039368724508917472734725552201;
    uint256 constant deltay1 = 1021089112864992604495371657504158008932424006616811742280456017737361059600;
    uint256 constant deltay2 = 13372486609920498606563305241486048805166507708947809832548722289143487776081;

    
    uint256 constant IC0x = 14444047502812324606642197536526392195870827449511342420845594483004547425573;
    uint256 constant IC0y = 8331232622364552169908286914025086114891902720457558873135677271713139105651;
    
    uint256 constant IC1x = 11878654429652714266207728145497831986228527326569791899633712398045259144773;
    uint256 constant IC1y = 8058894940882950171099990277367753953866865118325301179612638383151691609156;
    
    uint256 constant IC2x = 2727937804879239919404037344364991566656112907602357681567884177708379227701;
    uint256 constant IC2y = 1392216961244589707223086260415650306346138712556654176998356131916231678746;
    
    uint256 constant IC3x = 7877113030249216945299283966901013554735029341929159406703498284584499487224;
    uint256 constant IC3y = 11871601838968352674346379798588649255511860932588763434673523406251227443198;
    
    uint256 constant IC4x = 7394809793583545196668250376461142639328479388397196790312362931110173346637;
    uint256 constant IC4y = 14088505694584427397278516350046941073907607566846875397105077394382460218545;
    
    uint256 constant IC5x = 1010338523990599378953638901001733866065387514824849500459264189911738825752;
    uint256 constant IC5y = 13608879489751884597132679223122573215029322282094360317993272065884982331981;
    
    uint256 constant IC6x = 10081914778889473195192557721231090044877350526854347603344172302731383083943;
    uint256 constant IC6y = 12193030127407921847617989340520746701671868563446322708242929097319040101112;
    
    uint256 constant IC7x = 14207720985943239159156592226731008507028321145665205705006924767427257470313;
    uint256 constant IC7y = 1631108386858224286103670946250766186722070514103387108639391408081378861701;
    
    uint256 constant IC8x = 17857667421249413343624688870016216769181786408820901208073619820036577719129;
    uint256 constant IC8y = 6446101698854174591401700360309947439989134377613970752121974470289659285121;
    
    uint256 constant IC9x = 2553649132352651870761244504519938064213165452916588321975551734508452733166;
    uint256 constant IC9y = 2823979341845361238570836263376842206795246527412099813074968000544228257894;
    
    uint256 constant IC10x = 17125338215252924245215824985300642918339110911490624576653157432227081574859;
    uint256 constant IC10y = 6848680255155113880983058240611312273421981168252702154143622729086451536074;
    
    uint256 constant IC11x = 14303568373368599101489282422098661968905067875905867835367566183608811041491;
    uint256 constant IC11y = 11643071188772278186436622331374356189673462734184538157690502043362439043313;
    
    uint256 constant IC12x = 10444621257420368615532884643890471205599772183799057817166109809480477269714;
    uint256 constant IC12y = 8410179346258278579326988898436948547632440320677080986193144336038050144926;
    
    uint256 constant IC13x = 174262089512953093553564153213385755795814670674944738865461180650287415664;
    uint256 constant IC13y = 7883197273115665882027949518339220681531696420112004131258021012198239744007;
    
    uint256 constant IC14x = 3786119993852912233765381786886177827565683050983575553468980631446870638122;
    uint256 constant IC14y = 6725571099664506709165360193094253336528223022480875565024541569946008643022;
    
    uint256 constant IC15x = 11655717352650751096720371261469927718711189959040811939140005421076337977060;
    uint256 constant IC15y = 12177277461419382046700896104862001514242717045281096536892826336683560257070;
    
    uint256 constant IC16x = 1096435673128271339282520919639953640098457054209927364794647285995701521900;
    uint256 constant IC16y = 20828089418780565778351083961056952379193697748971271124445912545739987762761;
    
    uint256 constant IC17x = 18518367204631294413701586974176331464265443609966582094306997591497545768429;
    uint256 constant IC17y = 20804715984033608694468182991335702616321161420308715410292798152731562924271;
    
    uint256 constant IC18x = 19486880228145284804810651096800353285279698333828902977797710268824452867469;
    uint256 constant IC18y = 14783009456209746517248292449735819645089560410847449465102493316217888219081;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[18] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
