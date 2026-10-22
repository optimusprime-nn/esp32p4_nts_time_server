#include "unity.h"
#include "unity_test_runner.h"

void app_main(void)
{
    /* Runs every registered TEST_CASE once and prints the Unity summary
     * ("N Tests M Failures") on the console. */
    UNITY_BEGIN();
    unity_run_all_tests();
    UNITY_END();
}
