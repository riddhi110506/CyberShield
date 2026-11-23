from app.cvss_calculator import calculate_cvss_v3_1


print("=" * 60)
print("CYBERSHIELD CVSS CALCULATOR TEST")
print("=" * 60)


# Test 1: Critical vulnerability

result = calculate_cvss_v3_1(
    attack_vector="N",
    attack_complexity="L",
    privileges_required="N",
    user_interaction="N",
    scope="C",
    confidentiality="H",
    integrity="H",
    availability="H"
)

print("\nTEST 1")
print(result)


# Test 2: High vulnerability

result = calculate_cvss_v3_1(
    attack_vector="N",
    attack_complexity="L",
    privileges_required="N",
    user_interaction="R",
    scope="U",
    confidentiality="H",
    integrity="H",
    availability="H"
)

print("\nTEST 2")
print(result)


# Test 3: Medium vulnerability

result = calculate_cvss_v3_1(
    attack_vector="L",
    attack_complexity="H",
    privileges_required="L",
    user_interaction="R",
    scope="U",
    confidentiality="L",
    integrity="L",
    availability="N"
)

print("\nTEST 3")
print(result)


# Test 4: Low vulnerability

result = calculate_cvss_v3_1(
    attack_vector="P",
    attack_complexity="H",
    privileges_required="H",
    user_interaction="R",
    scope="U",
    confidentiality="L",
    integrity="N",
    availability="N"
)

print("\nTEST 4")
print(result)


print("\n" + "=" * 60)
print("TESTING COMPLETED")
print("=" * 60)
