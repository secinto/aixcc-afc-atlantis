# PCB

## Training

### Pre-requisites

- NVIDIA GPU with CUDA support
- Hugging Face authentication with Llama 3.2 access
- OpenAI API key
- wandb authentication
- [uv](https://docs.astral.sh/uv/)
- [global](https://www.gnu.org/software/global/)

### Procedure

1. Prepare the pre-requisites.
2. Clone the repository with submodules.
3. Run `uv sync` to synchronize the project.
4. Remove the line 1173-1182 `trl/trainer/grpo_trainer.py`.
5. Fill the `.env` file using the `.env.example` as a template.
6. Run `uv run scripts/preload.py` to preload the data.
7. Run `uv run scripts/train.py` to start the training process.

## Appendix

### Intended Removal of Code in `trl/trainer/grpo_trainer.py`

```diff
-        # If all reward functions return None for a given row, issue a detailed warning
-        if torch.isnan(rewards_per_func).all(dim=1).any():
-            nan_row_idx = torch.isnan(rewards_per_func).all(dim=1).nonzero(as_tuple=True)[0][0]
-            row_reward_kwargs = {key: value[nan_row_idx] for key, value in reward_kwargs.items()}
-            row_reward_kwargs["prompt"] = prompts[nan_row_idx]
-            row_reward_kwargs["completion"] = completions[nan_row_idx]
-            warnings.warn(
-                f"All reward functions returned None for the following kwargs: {row_reward_kwargs}. "
-                "Please ensure that at least one reward function returns a valid reward."
-            )
```
