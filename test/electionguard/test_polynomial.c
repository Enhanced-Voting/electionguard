#include "utils/utils.h"

#include <assert.h>
#include <electionguard/constants.h>
#include <electionguard/group.h>
#include <electionguard/polynomial.h>
#include <stdlib.h>

bool strings_are_equal(char *expected, char *actual);

static bool test_interpolate_with_no_other_degrees_returns_one(void);

bool test_polynomial(void)
{
    printf("\n -------- test_polynomial.c --------- \n");
    return test_interpolate_with_no_other_degrees_returns_one();
}

bool test_interpolate_with_no_other_degrees_returns_one(void)
{
    printf("\n -------- test_interpolate_with_no_other_degrees_returns_one -------- \n");

    // Arrange
    eg_element_mod_q_t *coordinate = NULL;
    if (eg_element_mod_q_from_uint64(1, &coordinate)) {
        assert(false);
    }

    eg_element_mod_q_t *one = NULL;
    if (eg_element_mod_q_constant_one_mod_q(&one)) {
        assert(false);
    }

    // Act
    // A single guardian has no other guardians' sequence orders to interpolate against.
    eg_element_mod_q_t *result = NULL;
    if (eg_polynomial_interpolate(coordinate, NULL, 0, &result)) {
        assert(false);
    }

    // Assert
    char *expected_hex = NULL;
    if (eg_element_mod_q_to_hex(one, &expected_hex)) {
        assert(false);
    }
    char *actual_hex = NULL;
    if (eg_element_mod_q_to_hex(result, &actual_hex)) {
        assert(false);
    }
    assert(strings_are_equal(expected_hex, actual_hex) == true);

    // Clean Up
    free(expected_hex);
    free(actual_hex);
    eg_element_mod_q_free(result);
    eg_element_mod_q_free(coordinate);

    return true;
}
