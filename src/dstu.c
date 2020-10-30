#include <openssl/engine.h>

static const char *engine_dstu_id = "dstu";
static const char *engine_dstu_name = "DSTU engine by Maksym Mamontov";

static int init(ENGINE *e)
{
    printf("DSTU engine initialization.\n");
    return 42;
}

static int bind(ENGINE *e, const char *id)
{
    if (!ENGINE_set_id(e, engine_dstu_id) ||
        !ENGINE_set_name(e, engine_dstu_name) ||
        !ENGINE_set_init_function(e, init))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
