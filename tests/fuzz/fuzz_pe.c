/* libFuzzer harness for the PE parser: `make fuzz FUZZ_TIME=600` (clang). */

#include "../../loader/pe/pe.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tw_pe_image im;
    tw_pe_error err;
    tw_pe_status st = tw_pe_parse(data, size, &im, &err);
    if (st != TW_PE_OK && st != TW_PE_ERR_MALFORMED && st != TW_PE_ERR_UNSUPPORTED) abort();
    /* touch the results so the optimizer cannot drop them */
    volatile size_t sink = im.nimports + im.exports.nentries + im.relocs.nentries + im.nwarnings;
    (void)sink;
    tw_pe_free(&im);
    return 0;
}
