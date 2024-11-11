<!-- CloseTab.vue -->
<template>
    <div>
        <h1>Please close this tab</h1>
        <p>This tab is no longer needed. You can close it now.</p>
    </div>
</template>
<script>export default {
    mounted() {
        // Optionally, you can try to close the tab here 
        setTimeout(() => {
            window.location.href = "https://www.google.com";
        }, 3000);
    }
} </script>