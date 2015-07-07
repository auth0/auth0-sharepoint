namespace Auth0.ClaimsProvider
{
    using System;
    using System.Collections.Generic;

    public static class Extensions
    {
        public static string UniqueEmail(this Auth0.User user)
        {
            return user.Email != null ? user.Email : user.UserId.Split('|')[1];
        }

        public static IEnumerable<TSource> DistinctBy<TSource, TKey>(this IEnumerable<TSource> source, Func<TSource, TKey> keySelector)
        {
            if (source == null)
            {
                throw new ArgumentNullException("source");
            }

            if (keySelector == null)
            {
                throw new ArgumentNullException("keySelector");
            }

            var knownKeys = new HashSet<TKey>();
            foreach (var element in source)
            {
                if (knownKeys.Add(keySelector(element)))
                {
                    yield return element;
                }
            }
        }
    }
}