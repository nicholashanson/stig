# Vortex-M (Visual Cortex-M)
Vortex-M is a full-featured soft-core implementation of the Cortex-M architecture.

It is intended for educational and artistic purposes.

The project supports the core Thumb2 instruction set.

<div align="center">
  <img src="assets/logo.png" width="400"><br>
</div>

## Build and Run
Vortex-M is written in DLang and built using dub. 

From the src subdirectory run:

```
  dub run -c=cortexm -- [path_to_elf_file] [soc] [addr] 
```
- [path_to_elf_file] : valid path to an elf file.
- [soc] : one of either "stm32" (for stm32f4X) or "nrf" (for nrf52X).
- [addr] : (optional) run to this address on start-up.

## Samples
You can get started by running one of the samples. 

For example, to run the blink LED FreeRTOS sample, from the src subdirectroy run:

```
  dub run -c=cortexm -- ../samples/stm32f4/freertos_blink.elf stm32
```
<div align="center">
  <img src="assets/demo_.GIF" width="400"><br>
</div>

