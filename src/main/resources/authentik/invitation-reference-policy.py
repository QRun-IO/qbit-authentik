# Authentik expression policy for the user-write stage binding.
# evaluate_on_plan=False, re_evaluate_policies=True, policy cache disabled.
# Execute after all enrollment prompts and immediately before user-write.
# Never derive this reference from submitted fields or URL parameters.
from uuid import UUID

plan = request.context.get("flow_plan")
if plan is None:
    return False

data = plan.context.setdefault("prompt_data", {})
data.pop("qqq_invitation_reference", None)
invitation = plan.context.get("invitation")
if not plan.context.get("invitation_in_effect") or invitation is None:
    return True

reference = (invitation.fixed_data or {}).get("qqq_invitation_reference")
try:
    if isinstance(reference, str) and str(UUID(reference)) == reference:
        data["qqq_invitation_reference"] = reference
except (ValueError, TypeError, AttributeError):
    pass
return True
