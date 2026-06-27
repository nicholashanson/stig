import Data.Word (Word32)
import Data.Bits
import Data.Word

sign_extend_12 :: Int -> Int
sign_extend_12 x =
    if x .&. 0x800 /= 0
        then x - 0x1000
    else x

type Reg = Int 

data Instr
    = Addi { rd :: Reg, rs1 :: Reg, imm :: Int }
    | Unknown Word32
    deriving (Show)

get_bits :: Word32 -> Int -> Int -> Word32
get_bits x hi lo =
    (x `shiftR` lo) .&. ((1 `shiftL` (hi - lo + 1)) - 1)

get_opcode :: Word32 -> Word8
get_opcode w = fromIntegral (w .&. 0x7F)

decode :: Word32 -> Instr 
decode w =
    case get_opcode w of 
        0x13 -> parse_addi w
        _    -> Unknown w

parse_addi :: Word32 -> Instr
parse_addi w = 
    let rd  = fromIntegral $ shiftR w 7  .&. 0x1F
        rs1 = fromIntegral $ shiftR w 15 .&. 0x1F
        imm = fromIntegral $ shiftR w 20 .&. 0xFFF
    in Addi rd rs1 (sign_extend_12 imm)

assert_addi :: Bool
assert_addi =
    case decode 0x020c8c93 of
        Addi rd rs1 imm ->
            rd == 25 && rs1 == 25 && imm == 32
        _ -> False