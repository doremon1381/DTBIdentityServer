namespace ServerUltilities
{
    public static class TaskUtilities
    {
        public static async Task<T> RunAttachedToParentTask<T>(Func<T> func)
        {
            return await Task.Factory.StartNew<T>(func, TaskCreationOptions.AttachedToParent);
        }

        public static async Task RunAttachedToParentTask(Action action)
        {
            await Task.Factory.StartNew(action, TaskCreationOptions.AttachedToParent);
        }
    }
}
