const MainRoutes = {
  path: '/main',
  meta: {
    requiresAuth: true
  },
  redirect: '/main/dashboard/default',
  component: () => import('@/layouts/full/FullLayout.vue'),
  children: [
    {
      name: 'LandingPage',
      path: '/',
      component: () => import('@/views/dashboards/default/DefaultDashboard.vue')
    },
    {
      name: 'Default',
      path: '/dashboard/default',
      component: () => import('@/views/dashboards/default/DefaultDashboard.vue')
    },
    {
      name: 'Starter',
      path: '/starter',
      component: () => import('@/views/StarterPage.vue')
    },
    // {
    //   name: 'Tabler Icons',
    //   path: '/icons/tabler',
    //   component: () => import('@/views/utilities/icons/TablerIcons.vue')
    // },
    // {
    //   name: 'Material Icons',
    //   path: '/icons/material',
    //   component: () => import('@/views/utilities/icons/MaterialIcons.vue')
    // },
    {
      name: 'Typography',
      path: '/utils/typography',
      component: () => import('@/views/utilities/typography/TypographyPage.vue')
    },
    {
      name: 'Shadows',
      path: '/utils/shadows',
      component: () => import('@/views/utilities/shadows/ShadowPage.vue')
    },
    {
      name: 'Colors',
      path: '/utils/colors',
      component: () => import('@/views/utilities/colors/ColorPage.vue')
    },
    // {
    //   name: 'Users',
    //   path: '/users',
    //   component: () => import('@/views/usergroup/UserManager.vue')
    // },
    // {
    //   name: 'Statistic',
    //   path: '/statistic',
    //   component: () => import('@/views/business/Statistic.vue')
    // },
    // {
    //   name: 'Storage',
    //   path: '/storage',
    //   component: () => import('@/views/business/StorageManager.vue')
    // },
    // {
    //   name: 'Delivery',
    //   path: '/delivery',
    //   component: () => import('@/views/business/Delivery.vue')
    // },
    // {
    //   name: 'Projects',
    //   path: '/projects',
    //   component: () => import('@/views/business/Projects.vue')
    // },
    // {
    //   name: 'Customers',
    //   path: '/customers',
    //   component: () => import('@/views/business/Customers.vue')
    // },
    // {
    //   name: 'Offices',
    //   path: '/offices',
    //   component: () => import('@/views/business/Offices.vue')
    // }
  ]
};

export default MainRoutes;
